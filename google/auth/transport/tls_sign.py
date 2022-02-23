import atexit
import base64
import cffi
import copy
import ctypes
import os
import re

from google.auth import environment_vars
from google.auth import exceptions
import requests

callback_type = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
)
custom_key_handle_type = ctypes.POINTER(ctypes.c_char)


def _cast_ssl_ctx_to_void_p(ssl_ctx):
    return ctypes.cast(int(cffi.FFI().cast("intptr_t", ssl_ctx)), ctypes.c_void_p)


def _load_offload_signing_ext():
    tls_offload_ext = None
    root_path = os.path.join(os.path.dirname(__file__), "../../../")
    for filename in os.listdir(root_path):
        if re.match("tls_offload_ext*", filename):
            tls_offload_ext = ctypes.CDLL(os.path.join(root_path, filename))
    if not tls_offload_ext:
        raise exceptions.MutualTLSChannelError(
            "tls_offload_ext shared library is not found"
        )
    tls_offload_ext.CreateCustomKey.argtypes = [callback_type]
    tls_offload_ext.CreateCustomKey.restype = custom_key_handle_type
    tls_offload_ext.DestroyCustomKey.argtypes = [custom_key_handle_type]
    return tls_offload_ext


def _load_windows_signer_ext():
    windows_signer_ext = None
    root_path = os.path.join(os.path.dirname(__file__), "../../../")
    for filename in os.listdir(root_path):
        if re.match("windows_signer_ext*", filename):
            windows_signer_ext = ctypes.CDLL(os.path.join(root_path, filename))
    if not windows_signer_ext:
        raise exceptions.MutualTLSChannelError(
            "windows_signer_ext shared library is not found"
        )
    windows_signer_ext.CreateCustomKey.restype = custom_key_handle_type
    windows_signer_ext.DestroyCustomKey.argtypes = [custom_key_handle_type]
    return windows_signer_ext


def _create_pkcs11_sign_callback(key_info):
    def sign_callback(sig, sig_len, tbs, tbs_len):
        print("calling pkcs11 signer....")

        import pkcs11
        from pkcs11 import KeyType, Mechanism, MGF
        from pkcs11.constants import ObjectClass
        import pkcs11.util.ec
        from cryptography.hazmat.primitives import hashes

        lib = pkcs11.lib(key_info["module_path"])
        token = lib.get_token(token_label=key_info["token_label"])
        user_pin = key_info["user_pin"] if "user_pin" in key_info else None

        # Open a session on our token
        with token.open(user_pin=user_pin) as session:
            key = session.get_key(
                label=key_info["key_label"], object_class=ObjectClass.PRIVATE_KEY
            )
            data = ctypes.string_at(tbs, tbs_len)
            hash = hashes.Hash(hashes.SHA256())
            hash.update(data)
            digest = hash.finalize()
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

            # reset pkcs11 lib
            pkcs11._lib = None

            return 1

    return callback_type(sign_callback)


def _create_raw_sign_callback(key_info):
    def sign_callback(sig, sig_len, tbs, tbs_len):
        print("calling raw key signer....")

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.asymmetric import ec

        with open(key_info["pem_path"], "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )

        data = ctypes.string_at(tbs, tbs_len)
        hash = hashes.Hash(hashes.SHA256())
        hash.update(data)
        digest = hash.finalize()

        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=len(digest)),
                hashes.SHA256(),
            )
        else:
            signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        sig_len[0] = len(signature)
        if sig:
            for i in range(len(signature)):
                sig[i] = signature[i]

        return 1

    return callback_type(sign_callback)


def _create_win_golang_sign_callback(key_info):
    def sign_callback(sig, sig_len, tbs, tbs_len):
        print("calling golang windows key signer....")

        from cryptography.hazmat.primitives import hashes

        data = ctypes.string_at(tbs, tbs_len)
        hash = hashes.Hash(hashes.SHA256())
        hash.update(data)
        digest = hash.finalize()
        digestArray = ctypes.c_char * len(digest)

        import os
        dll_path = os.getenv(environment_vars.GOOGLE_AUTH_SIGNER_LIBRARY_PATH)
        lib = ctypes.CDLL(dll_path)
        if not lib:
            raise exceptions.MutualTLSChannelError("GOOGLE_AUTH_SIGNER_LIBRARY_PATH dll is not found")
        lib.SignForPython.restype = ctypes.c_int
        lib.SignForPython.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        ]

        issuer = key_info["issuer"].encode()
        storeName = key_info["store_name"].encode()
        provider = key_info["provider"].encode()
        sigHolder = ctypes.create_string_buffer(2000)
        sigLen = lib.SignForPython(
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

    return callback_type(sign_callback)


def _create_mac_golang_sign_callback(key_info):
    def sign_callback(sig, sig_len, tbs, tbs_len):
        print("calling golang MacOS key signer....")

        from cryptography.hazmat.primitives import hashes

        data = ctypes.string_at(tbs, tbs_len)
        hash = hashes.Hash(hashes.SHA256())
        hash.update(data)
        digest = hash.finalize()
        digestArray = ctypes.c_char * len(digest)

        import os
        dll_path = os.getenv(environment_vars.GOOGLE_AUTH_SIGNER_LIBRARY_PATH)
        lib = ctypes.CDLL(dll_path)
        if not lib:
            raise exceptions.MutualTLSChannelError("GOOGLE_AUTH_SIGNER_LIBRARY_PATH is not set or doesn't exist")
        lib.SignForPython.restype = ctypes.c_int
        lib.SignForPython.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        ]

        issuer = key_info["issuer"].encode()
        sigHolder = ctypes.create_string_buffer(2000)
        sigLen = lib.SignForPython(
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

    return callback_type(sign_callback)


def _create_daemon_sign_callback(key_info):
    def sign_callback(sig, sig_len, tbs, tbs_len):
        print("calling daemon signer....")

        body = copy.deepcopy(key_info)
        data = ctypes.string_at(tbs, tbs_len)
        body["data"] = base64.encodebytes(data).decode("ascii")
        daemon_sign_endpoint = os.getenv("DAEMON_SIGN_ENDPOINT")

        res = requests.post(daemon_sign_endpoint, json=body)
        if not res.ok:
            return 0

        signature = res.json()["signature"]
        signature = base64.b64decode(signature)

        sig_len[0] = len(signature)
        if sig:
            for i in range(len(signature)):
                sig[i] = signature[i]

        return 1

    return callback_type(sign_callback)


class CustomSigner(object):
    def __init__(self, cert, key):
        key_info = key["key_info"]
        self.offload_signing_ext = _load_offload_signing_ext()
        self.offload_signing_function = self.offload_signing_ext.OffloadSigning

        # Select the right signer based on the key type
        if key["type"] == "pkcs11":
            self.sign_callback = _create_pkcs11_sign_callback(key_info)
        elif key["type"] == "raw":
            self.sign_callback = _create_raw_sign_callback(key_info)
        elif key["type"] == "daemon":
            self.sign_callback = _create_daemon_sign_callback(key_info)
        elif key["type"] == "windows_cert_store":
            self.sign_callback = _create_win_golang_sign_callback(key_info)
        elif key["type"] == "macos_keychain":
            self.sign_callback = _create_mac_golang_sign_callback(key_info)
        else:
            raise exceptions.MutualTLSChannelError(
                "currently only pkcs11, raw, daemon, macos_keychain and windows_cert_store type are supported"
            )
        self.signer = self.offload_signing_ext.CreateCustomKey(self.sign_callback)
        self.cleanup_func = self.offload_signing_ext.DestroyCustomKey
        atexit.register(self.cleanup)

        # # old C++ code
        # if key["type"] == "windows_cert_store":
        #     if not key_info["provider"] in ["local_machine", "current_user"]:
        #         raise exceptions.MutualTLSChannelError(
        #             key_info["provider"] + " is not supported"
        #         )
        #     from cryptography import x509
        #     from cryptography.hazmat.primitives.asymmetric import rsa

        #     self.offload_signing_function = self.offload_signing_ext.OffloadSigning
        #     self.windows_signer_ext = _load_windows_signer_ext()

        #     public_key = x509.load_pem_x509_certificate(cert).public_key()
        #     is_rsa = isinstance(public_key, rsa.RSAPublicKey)
        #     is_local_machine_store = key_info["provider"] == "local_machine"
        #     self.signer = self.windows_signer_ext.CreateCustomKey(
        #         ctypes.c_bool(is_rsa),
        #         ctypes.c_bool(is_local_machine_store),
        #         ctypes.c_char_p(key_info["store_name"].encode()),
        #         ctypes.c_char_p(key_info["subject"].encode()),
        #     )
        #     self.cleanup_func = self.windows_signer_ext.DestroyCustomKey
        #     atexit.register(self.cleanup)

    def cleanup(self):
        if self.signer:
            self.cleanup_func(self.signer)


def attach_signer_and_cert_to_ssl_context(signer, cert, ctx):
    if not signer.offload_signing_function(
        signer.signer, ctypes.c_char_p(cert), _cast_ssl_ctx_to_void_p(ctx._ctx._context)
    ):
        raise exceptions.MutualTLSChannelError("failed to offload signing")


def get_cert_from_store(key):
    if key["type"] not in ["windows_cert_store", "macos_keychain"]:
        return None

    import os
    dll_path = os.getenv(environment_vars.GOOGLE_AUTH_SIGNER_LIBRARY_PATH)
    lib = ctypes.CDLL(dll_path)
    if not lib:
        raise exceptions.MutualTLSChannelError("GOOGLE_AUTH_SIGNER_LIBRARY_PATH is not set or doesn't exist")

    if key["type"] == "windows_cert_store":
        issuer = key["key_info"]["issuer"].encode()
        storeName = key["key_info"]["store_name"].encode()
        provider = key["key_info"]["provider"].encode()

        lib.GetCertPemForPython.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        lib.GetCertPemForPython.restype = ctypes.c_int

        # First call to calculate the cert length
        certLen = lib.GetCertPemForPython(
            ctypes.c_char_p(issuer),
            ctypes.c_char_p(storeName),
            ctypes.c_char_p(provider),
            None,
            0,
        )
        if certLen > 0:
            # Then we create an array to hold the cert, and call again to fill the cert
            certHolder = ctypes.create_string_buffer(certLen)
            lib.GetCertPemForPython(
                ctypes.c_char_p(issuer),
                ctypes.c_char_p(storeName),
                ctypes.c_char_p(provider),
                certHolder,
                certLen,
            )
            return bytes(certHolder)
    else:
        issuer = key["key_info"]["issuer"].encode()

        lib.GetCertPemForPython.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        lib.GetCertPemForPython.restype = ctypes.c_int

        # First call to calculate the cert length
        certLen = lib.GetCertPemForPython(
            ctypes.c_char_p(issuer),
            None,
            0,
        )
        if certLen > 0:
            # Then we create an array to hold the cert, and call again to fill the cert
            certHolder = ctypes.create_string_buffer(certLen)
            lib.GetCertPemForPython(
                ctypes.c_char_p(issuer),
                certHolder,
                certLen,
            )
            return bytes(certHolder)
    return None
