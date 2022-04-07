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

import atexit
import ctypes
import logging
import os
import sys

import cffi

from google.auth import environment_vars
from google.auth import exceptions

_LOGGER = logging.getLogger(__name__)

SIGN_CALLBACK_CTYPE = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
)
CUSTOM_KEY_CTYPE = ctypes.POINTER(ctypes.c_char)


def _cast_ssl_ctx_to_void_p(ssl_ctx):
    return ctypes.cast(int(cffi.FFI().cast("intptr_t", ssl_ctx)), ctypes.c_void_p)


def validate_key_format(key):
    if key["type"] not in ["windows_cert_store", "macos_keychain", "pkcs11"]:
        raise exceptions.MutualTLSChannelError(
            "key type {} is not supported".format(key["type"])
        )


def load_offload_lib():
    offload_lib_path = os.getenv(environment_vars.GOOGLE_AUTH_OFFLOAD_LIBRARY_PATH)
    if not offload_lib_path:
        raise exceptions.MutualTLSChannelError(
            "GOOGLE_AUTH_OFFLOAD_LIBRARY_PATH is not set"
        )
    _LOGGER.debug("loading offload library from %s", offload_lib_path)

    # winmode parameter is only available for python 3.8+.
    lib = (
        ctypes.CDLL(offload_lib_path, winmode=0)
        if sys.version_info >= (3, 8) and os.name == "nt"
        else ctypes.CDLL(offload_lib_path)
    )

    lib.CreateCustomKey.argtypes = [SIGN_CALLBACK_CTYPE]
    lib.CreateCustomKey.restype = CUSTOM_KEY_CTYPE
    lib.DestroyCustomKey.argtypes = [CUSTOM_KEY_CTYPE]
    return lib


def load_signer_lib(key):
    if key["type"] == "pkcs11":
        return None

    signer_lib_path = os.getenv(environment_vars.GOOGLE_AUTH_SIGNER_LIBRARY_PATH)
    if not signer_lib_path:
        raise exceptions.MutualTLSChannelError(
            "GOOGLE_AUTH_SIGNER_LIBRARY_PATH is not set"
        )
    _LOGGER.debug("loading signer library from %s", signer_lib_path)

    # winmode parameter is only available for python 3.8+.
    lib = (
        ctypes.CDLL(signer_lib_path, winmode=0)
        if sys.version_info >= (3, 8) and os.name == "nt"
        else ctypes.CDLL(signer_lib_path)
    )

    lib.SignForPython.restype = ctypes.c_int
    lib.GetCertPemForPython.restype = ctypes.c_int

    if key["type"] == "windows_cert_store":
        # Parameters are: issuer, storeName, provider, digest, digestLen,
        # sigHolder, sigHolderLen
        lib.SignForPython.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        # Parameters are: issuer, storeName, provider, certHolder, certLen
        lib.GetCertPemForPython.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
    else:
        # MacOS
        # Parameters are: issuer, digest, digestLen, sigHolder, sigHolderLen
        lib.SignForPython.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        # Parameters are: issuer, storeName, provider, certHolder, certLen
        lib.GetCertPemForPython.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
    return lib


def _compute_sha256_digest(to_be_signed, to_be_signed_len):
    from cryptography.hazmat.primitives import hashes

    data = ctypes.string_at(to_be_signed, to_be_signed_len)
    hash = hashes.Hash(hashes.SHA256())
    hash.update(data)
    return hash.finalize()


def _get_pkcs11_sign_callback(key):
    key_info = key["key_info"]

    def sign_callback(sig, sig_len, tbs, tbs_len):
        _LOGGER.debug("calling pkcs11 signer....")

        import pkcs11
        from pkcs11 import KeyType, Mechanism, MGF
        from pkcs11.constants import ObjectClass
        import pkcs11.util.ec

        lib = pkcs11.lib(key_info["module_path"])
        token = lib.get_token(token_label=key_info["token_label"])
        user_pin = key_info["user_pin"] if "user_pin" in key_info else None

        # Open a session on our token
        with token.open(user_pin=user_pin) as session:
            key = session.get_key(
                label=key_info["key_label"], object_class=ObjectClass.PRIVATE_KEY
            )
            digest = _compute_sha256_digest(tbs, tbs_len)
            if key.key_type == KeyType.RSA:
                signature = key.sign(
                    digest,
                    mechanism=Mechanism.RSA_PKCS_PSS,
                    mechanism_param=(Mechanism.SHA256, MGF.SHA256, len(digest)),
                )
            else:
                signature = key.sign(digest, mechanism=Mechanism.ECDSA)
                signature = pkcs11.util.ec.encode_ecdsa_signature(signature)
            sig_len[0] = len(signature)
            if sig:
                for i in range(len(signature)):
                    sig[i] = signature[i]

            return 1

    return sign_callback


def _get_win_cert_store_sign_callback(key, signer_lib):
    def sign_callback(sig, sig_len, tbs, tbs_len):
        _LOGGER.debug("calling windows cert store sign callback...")

        digest = _compute_sha256_digest(tbs, tbs_len)
        digestArray = ctypes.c_char * len(digest)

        key_info = key["key_info"]
        issuer = key_info["issuer"].encode()
        storeName = key_info["store_name"].encode()
        provider = key_info["provider"].encode()
        sigHolder = ctypes.create_string_buffer(2000)
        sigLen = signer_lib.SignForPython(
            ctypes.c_char_p(issuer),
            ctypes.c_char_p(storeName),
            ctypes.c_char_p(provider),
            digestArray.from_buffer(bytearray(digest)),
            len(digest),
            sigHolder,
            2000,
        )

        sig_len[0] = sigLen
        if sig:
            bs = bytearray(sigHolder)
            for i in range(sigLen):
                sig[i] = bs[i]

        return 1

    return sign_callback


def _get_macos_keychain_sign_callback(key, signer_lib):
    def sign_callback(sig, sig_len, tbs, tbs_len):
        _LOGGER.debug("calling MacOS keychain sign callback...")

        from cryptography.hazmat.primitives import hashes

        data = ctypes.string_at(tbs, tbs_len)
        hash = hashes.Hash(hashes.SHA256())
        hash.update(data)
        digest = hash.finalize()
        digestArray = ctypes.c_char * len(digest)

        issuer = key["key_info"]["issuer"].encode()
        sigHolder = ctypes.create_string_buffer(2000)
        sigLen = signer_lib.SignForPython(
            ctypes.c_char_p(issuer),
            digestArray.from_buffer(bytearray(digest)),
            len(digest),
            sigHolder,
            2000,
        )

        sig_len[0] = sigLen
        if sig:
            bs = bytearray(sigHolder)
            for i in range(sigLen):
                sig[i] = bs[i]

        return 1

    return sign_callback


def get_sign_callback(key, signer_lib):
    if key["type"] == "pkcs11":
        sign_callback = _get_pkcs11_sign_callback(key)
    elif key["type"] == "windows_cert_store":
        sign_callback = _get_win_cert_store_sign_callback(key, signer_lib)
    else:
        sign_callback = _get_macos_keychain_sign_callback(key, signer_lib)
    return SIGN_CALLBACK_CTYPE(sign_callback)


def _get_cert_from_pkcs11(key):
    import pkcs11
    from pkcs11.constants import Attribute
    from pkcs11.constants import ObjectClass
    import OpenSSL

    key_info = key["key_info"]
    lib = pkcs11.lib(key_info["module_path"])
    token = lib.get_token(token_label=key_info["token_label"])
    user_pin = key_info["user_pin"] if "user_pin" in key_info else None

    # Open a session on our token
    with token.open(user_pin=user_pin) as session:
        for cert in session.get_objects(
            {
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.LABEL: key_info["key_label"],
            }
        ):
            cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, cert[Attribute.VALUE]
            )
            cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            return cert
    return None


def _get_cert_from_windows_cert_store(key, signer_lib):
    key_info = key["key_info"]
    issuer = key_info["issuer"].encode()
    storeName = key_info["store_name"].encode()
    provider = key_info["provider"].encode()

    # First call to calculate the cert length
    certLen = signer_lib.GetCertPemForPython(
        ctypes.c_char_p(issuer),
        ctypes.c_char_p(storeName),
        ctypes.c_char_p(provider),
        None,
        0,
    )
    if certLen > 0:
        # Then we create an array to hold the cert, and call again to fill the cert
        certHolder = ctypes.create_string_buffer(certLen)
        signer_lib.GetCertPemForPython(
            ctypes.c_char_p(issuer),
            ctypes.c_char_p(storeName),
            ctypes.c_char_p(provider),
            certHolder,
            certLen,
        )
        return bytes(certHolder)
    return None


def _get_cert_from_macos_keychain(key, signer_lib):
    issuer = key["key_info"]["issuer"].encode()

    # First call to calculate the cert length
    certLen = signer_lib.GetCertPemForPython(ctypes.c_char_p(issuer), None, 0)
    if certLen > 0:
        # Then we create an array to hold the cert, and call again to fill the cert
        certHolder = ctypes.create_string_buffer(certLen)
        signer_lib.GetCertPemForPython(ctypes.c_char_p(issuer), certHolder, certLen)
        return bytes(certHolder)
    return None


def get_cert(key, signer_lib):
    if key["type"] == "pkcs11":
        return _get_cert_from_pkcs11(key)
    elif key["type"] == "windows_cert_store":
        return _get_cert_from_windows_cert_store(key, signer_lib)
    return _get_cert_from_macos_keychain(key, signer_lib)


class CustomTlsSigner(object):
    def __init__(self, cert, key):
        validate_key_format(key)

        self.cert = cert
        self.key = key
        self.offload_lib = load_offload_lib()
        self.signer_lib = load_signer_lib(key)

        atexit.register(self.cleanup)

    def set_up_ssl_context(self, ctx):
        # Get cert using signer lib if cert is not provided.
        if not self.cert:
            self.cert = get_cert(self.key, self.signer_lib)

        # We need to keep a reference of sign_callback so it won't get garbage
        # collected, otherwise it will crash when it gets call in signer lib.
        self.sign_callback = get_sign_callback(self.key, self.signer_lib)

        # Custom key is created in heap by offload lib, so we must call the
        # destroy method from offload lib on exit.
        self.custom_key = self.offload_lib.CreateCustomKey(self.sign_callback)

        # Add custom_key and cert to SSL context. In the TLS handshake, the
        # signing operation will be done by the sign_callback in custom_key.
        if not self.offload_lib.OffloadSigning(
            self.custom_key,
            ctypes.c_char_p(self.cert),
            _cast_ssl_ctx_to_void_p(ctx._ctx._context),
        ):
            raise exceptions.MutualTLSChannelError("failed to offload signing")

    def cleanup(self):
        if self.custom_key:
            self.offload_lib.DestroyCustomKey(self.custom_key)
