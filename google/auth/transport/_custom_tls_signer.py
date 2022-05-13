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

"""Experimental code for offloading client side TLS signing operation to signing
libraries.
"""

import ctypes
import json
import logging
import os
import sys

import cffi
import six

from google.auth import exceptions

_LOGGER = logging.getLogger(__name__)

SIGN_CALLBACK_CTYPE = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
)


def _cast_ssl_ctx_to_void_p(ssl_ctx):
    return ctypes.cast(int(cffi.FFI().cast("intptr_t", ssl_ctx)), ctypes.c_void_p)


def load_offload_lib(offload_lib_path):
    _LOGGER.debug("loading offload library from %s", offload_lib_path)

    # winmode parameter is only available for python 3.8+.
    lib = (
        ctypes.CDLL(offload_lib_path, winmode=0)
        if sys.version_info >= (3, 8) and os.name == "nt"
        else ctypes.CDLL(offload_lib_path)
    )

    lib.ConfigureSslContext.argtypes = [
        SIGN_CALLBACK_CTYPE,
        ctypes.c_char_p,
        ctypes.c_void_p,
    ]
    lib.ConfigureSslContext.restype = ctypes.c_int
    return lib


def load_signer_lib(signer_lib_path):
    _LOGGER.debug("loading signer library from %s", signer_lib_path)

    # winmode parameter is only available for python 3.8+.
    lib = (
        ctypes.CDLL(signer_lib_path, winmode=0)
        if sys.version_info >= (3, 8) and os.name == "nt"
        else ctypes.CDLL(signer_lib_path)
    )

    # Arguments are: certHolder, certHolderLen
    lib.GetCertPemForPython.argtypes = [ctypes.c_char_p, ctypes.c_int]
    # Returns: certLen
    lib.GetCertPemForPython.restype = ctypes.c_int

    # Arguments are: digest, digestLen, sigHolder, sigHolderLen
    lib.SignForPython.argtypes = [
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    # Returns: 1 if signing operation is successful, otherwise 0
    lib.SignForPython.restype = ctypes.c_int

    return lib


def _compute_sha256_digest(to_be_signed, to_be_signed_len):
    from cryptography.hazmat.primitives import hashes

    data = ctypes.string_at(to_be_signed, to_be_signed_len)
    hash = hashes.Hash(hashes.SHA256())
    hash.update(data)
    return hash.finalize()


def get_sign_callback(signer_lib):
    def sign_callback(sig, sig_len, tbs, tbs_len):
        _LOGGER.debug("calling sign callback...")

        digest = _compute_sha256_digest(tbs, tbs_len)
        digestArray = ctypes.c_char * len(digest)

        # reserve 2000 bytes for the signature, shoud be more then enough
        sigHolder = ctypes.create_string_buffer(2000)

        sigLen = signer_lib.SignForPython(
            digestArray.from_buffer(bytearray(digest)), len(digest), sigHolder, 2000
        )

        sig_len[0] = sigLen
        bs = bytearray(sigHolder)
        for i in range(sigLen):
            sig[i] = bs[i]

        return 1

    return sign_callback


def get_cert(signer_lib):
    # First call to calculate the cert length
    certLen = signer_lib.GetCertPemForPython(None, 0)
    if certLen == 0:
        raise exceptions.MutualTLSChannelError("failed to get certificate")

    # Then we create an array to hold the cert, and call again to fill the cert
    certHolder = ctypes.create_string_buffer(certLen)
    signer_lib.GetCertPemForPython(certHolder, certLen)
    return bytes(certHolder)


class CustomTlsSigner(object):
    def __init__(self, enterprise_cert_file_path):
        """
        This class loads the offload and signer library, and calls APIs from
        these libraries to obtain the cert and the custom key. The cert and
        the custom key are then attached to SSL context. In the TLS handshake
        stage, the custom key's sign method will be called to genereate
        signature.

        Args:
            enterprise_cert_file_path (str): the path to a enterprise cert JSON
                file. The file should contain the following field:

                    {
                        "libs": {
                            "signer_library": "...",
                            "offload_library": "..."
                        }
                    }
        """
        self._enterprise_cert_file_path = enterprise_cert_file_path
        self._cert = None
        self._sign_callback = None

    def load_libraries(self):
        try:
            with open(self._enterprise_cert_file_path, "r") as f:
                enterprise_cert_json = json.load(f)
                libs = enterprise_cert_json["libs"]
                signer_library = libs["signer_library"]
                offload_library = libs["offload_library"]
        except (KeyError, ValueError) as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(
                "enterprise cert file is invalid", caught_exc
            )
            six.raise_from(new_exc, caught_exc)
        self._offload_lib = load_offload_lib(offload_library)
        self._signer_lib = load_signer_lib(signer_library)

    def set_up_custom_key(self):
        # We need to keep a reference of the cert and sign callback so it won't
        # be garbage collected, otherwise it will crash when used by signer lib.
        # Get cert using signer lib.
        self._cert = get_cert(self._signer_lib)
        self._sign_callback = get_sign_callback(self._signer_lib)

    def attach_to_ssl_context(self, ctx):
        # In the TLS handshake, the signing operation will be done by the
        # sign_callback.
        if not self._offload_lib.ConfigureSslContext(
            self._sign_callback,
            ctypes.c_char_p(self._cert),
            _cast_ssl_ctx_to_void_p(ctx._ctx._context),
        ):
            raise exceptions.MutualTLSChannelError("failed to configure SSL context")
