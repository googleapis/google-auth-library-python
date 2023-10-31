# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Code for configuring client side TLS to offload the signing operation to
signing libraries.
"""

import ctypes
import json
import logging
import os
import sys

import cffi  # type: ignore

from google.auth import exceptions

_LOGGER = logging.getLogger(__name__)


# Cast SSL_CTX* to void*
def _cast_ssl_ctx_to_void_p(ssl_ctx):
    return ctypes.cast(int(cffi.FFI().cast("intptr_t", ssl_ctx)), ctypes.c_void_p)


# Load offload library and set up the function types.
def load_provider_lib(provider_lib_path):
    _LOGGER.debug("loading provider library from %s", provider_lib_path)

    # winmode parameter is only available for python 3.8+.
    lib = (
        ctypes.CDLL(provider_lib_path, winmode=0)
        if sys.version_info >= (3, 8) and os.name == "nt"
        else ctypes.CDLL(provider_lib_path)
    )

    lib.ECP_attach_to_ctx.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ECP_attach_to_ctx.restype = ctypes.c_int

    return lib


class CustomTlsSigner(object):
    def __init__(self, enterprise_cert_file_path):
        """
        This class loads the offload and signer library, and calls APIs from
        these libraries to obtain the cert and a signing callback, and attach
        them to SSL context. The cert and the signing callback will be used
        for client authentication in TLS handshake.

        Args:
            enterprise_cert_file_path (str): the path to a enterprise cert JSON
                file. The file should contain the following field:

                    {
                        "libs": {
                            "ecp_client": "...",
                            "tls_offload": "..."
                        }
                    }
        """
        self._enterprise_cert_file_path = enterprise_cert_file_path
        self._provider_lib = None

    def load_libraries(self):
        try:
            with open(self._enterprise_cert_file_path, "r") as f:
                enterprise_cert_json = json.load(f)
                libs = enterprise_cert_json["libs"]
                provider_library = libs["ecp_provider"]
        except (KeyError, ValueError) as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(
                "enterprise cert file is invalid", caught_exc
            )
            raise new_exc from caught_exc
        self._provider_lib = load_provider_lib(provider_library)

    def attach_to_ssl_context(self, ctx):
        if not self._provider_lib.ECP_attach_to_ctx(
            _cast_ssl_ctx_to_void_p(ctx._ctx._context),
            self._enterprise_cert_file_path.encode("ascii"),
        ):
            raise exceptions.MutualTLSChannelError("failed to configure SSL context")
