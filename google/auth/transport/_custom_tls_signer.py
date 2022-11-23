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

import six

from google.auth import exceptions

_LOGGER = logging.getLogger(__name__)

# Load signer library and set up the function types.
# See: https://github.com/googleapis/enterprise-certificate-proxy/blob/main/cshared/main.go
def load_signer_lib(signer_lib_path):
    _LOGGER.debug("loading signer library from %s", signer_lib_path)

    # winmode parameter is only available for python 3.8+.
    lib = (
        ctypes.CDLL(signer_lib_path, winmode=0)
        if sys.version_info >= (3, 8) and os.name == "nt"
        else ctypes.CDLL(signer_lib_path)
    )

    # Set up types for:
    # func GetCertPemForPython(configFilePath *C.char, certHolder *byte, certHolderLen int)
    lib.GetCertPemForPython.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    # Returns: certLen
    lib.GetCertPemForPython.restype = ctypes.c_int

    # Set up types for:
    # func SignForPython(configFilePath *C.char, digest *byte, digestLen int,
    #     sigHolder *byte, sigHolderLen int)
    lib.SignForPython.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    # Returns: the signature length
    lib.SignForPython.restype = ctypes.c_int

    return lib


# Computes SHA256 hash.
def _compute_sha256_digest(to_be_signed, to_be_signed_len):
    from cryptography.hazmat.bindings._openssl import ffi
    from cryptography.hazmat.primitives import hashes

    data = bytes(ffi.buffer(to_be_signed, to_be_signed_len))
    hash = hashes.Hash(hashes.SHA256())
    hash.update(data)
    return hash.finalize()


# Create the signing callback. The actual signing work is done by the
# `SignForPython` method from the signer lib.
def get_sign_callback(signer_lib, config_file_path):
    from cryptography.hazmat.bindings._openssl import ffi
    @ffi.callback("int(unsigned char *sig, size_t *sig_len,const unsigned char *tbs, size_t tbs_len)")
    def sign_callback(sig, sig_len, tbs, tbs_len):
        _LOGGER.debug("calling sign callback...")

        digest = _compute_sha256_digest(tbs, tbs_len)
        digestArray = ctypes.c_char * len(digest)

        # reserve 2000 bytes for the signature, shoud be more then enough.
        # RSA signature is 256 bytes, EC signature is 70~72.
        sig_holder_len = 2000
        sig_holder = ctypes.create_string_buffer(sig_holder_len)

        signature_len = signer_lib.SignForPython(
            config_file_path.encode(),  # configFilePath
            digestArray.from_buffer(bytearray(digest)),  # digest
            len(digest),  # digestLen
            sig_holder,  # sigHolder
            sig_holder_len,  # sigHolderLen
        )

        if signature_len == 0:
            # signing failed, return 0
            return 0

        sig_len[0] = signature_len
        if sig:
            bs = bytearray(sig_holder)
            for i in range(signature_len):
                sig[i] = bs[i]

        return 1

    return sign_callback


# Obtain the certificate bytes by calling the `GetCertPemForPython` method from
# the signer lib. The method is called twice, the first time is to compute the
# cert length, then we create a buffer to hold the cert, and call it again to
# fill the buffer.
def get_cert(signer_lib, config_file_path):
    # First call to calculate the cert length
    cert_len = signer_lib.GetCertPemForPython(
        config_file_path.encode(),  # configFilePath
        None,  # certHolder
        0,  # certHolderLen
    )
    if cert_len == 0:
        raise exceptions.MutualTLSChannelError("failed to get certificate")

    # Then we create an array to hold the cert, and call again to fill the cert
    cert_holder = ctypes.create_string_buffer(cert_len)
    signer_lib.GetCertPemForPython(
        config_file_path.encode(),  # configFilePath
        cert_holder,  # certHolder
        cert_len,  # certHolderLen
    )
    return bytes(cert_holder)


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
                signer_library = libs["ecp_client"]
        except (KeyError, ValueError) as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(
                "enterprise cert file is invalid", caught_exc
            )
            six.raise_from(new_exc, caught_exc)
        self._signer_lib = load_signer_lib(signer_library)

    def set_up_custom_key(self):
        # We need to keep a reference of the cert and sign callback so it won't
        # be garbage collected, otherwise it will crash when used by signer lib.
        self._cert = get_cert(self._signer_lib, self._enterprise_cert_file_path)
        self._sign_callback = get_sign_callback(
            self._signer_lib, self._enterprise_cert_file_path
        )

    def attach_to_ssl_context(self, ctx):
        # In the TLS handshake, the signing operation will be done by the
        # sign_callback.
        print("calling attach_to_ssl_context")
        from cryptography.hazmat.bindings._openssl import lib
        if not lib.ConfigureSslContext(
            self._sign_callback,
            self._cert,
            ctx._ctx._context,
        ):
            raise exceptions.MutualTLSChannelError("failed to configure SSL context")
