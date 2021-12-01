import atexit
import cffi
import ctypes
import os
import re

from google.auth import exceptions


def _cast_ssl_ctx_to_void_p(ssl_ctx):
    return ctypes.cast(int(cffi.FFI().cast("intptr_t", ssl_ctx)), ctypes.c_void_p)


def offload_signing_ext():
    tls_offload_ext = None
    root_path = os.path.join(os.path.dirname(__file__), "../../../")
    for filename in os.listdir(root_path):
        if re.match("tls_offload_ext*", filename):
            tls_offload_ext = ctypes.CDLL(os.path.join(root_path, filename))
    if not tls_offload_ext:
        raise exceptions.MutualTLSChannelError(
            "tls_offload_ext shared library is not found"
        )
    custom_key_handle = ctypes.POINTER(ctypes.c_char)
    callback_type = ctypes.CFUNCTYPE(
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
    )
    tls_offload_ext.CreateCustomKey.argtypes = [callback_type]
    tls_offload_ext.CreateCustomKey.restype = custom_key_handle
    tls_offload_ext.DestroyCustomKey.argtypes = [custom_key_handle]
    return tls_offload_ext

def windows_signer_ext():
    windows_signer_ext = None
    root_path = os.path.join(os.path.dirname(__file__), "../../../")
    for filename in os.listdir(root_path):
        if re.match("windows_signer_ext*", filename):
            windows_signer_ext = ctypes.CDLL(os.path.join(root_path, filename))
    if not windows_signer_ext:
        raise exceptions.MutualTLSChannelError(
            "windows_signer_ext shared library is not found"
        )
    custom_key_handle = ctypes.POINTER(ctypes.c_char)
    callback_type = ctypes.CFUNCTYPE(
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
    )
    windows_signer_ext.CreateCustomKey.restype = custom_key_handle
    windows_signer_ext.DestroyCustomKey.argtypes = [custom_key_handle]
    return windows_signer_ext


def _create_pkcs11_sign_callback(key_info):
    callback_type = ctypes.CFUNCTYPE(
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
    )

    def sign_callback(sig, sig_len, tbs, tbs_len):
        import pkcs11
        from pkcs11 import KeyType, Mechanism, MGF
        from pkcs11.constants import ObjectClass
        import pkcs11.util.ec
        from cryptography.hazmat.primitives import hashes

        print("calling sign_callback....\n")

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
    callback_type = ctypes.CFUNCTYPE(
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
    )

    def sign_callback(sig, sig_len, tbs, tbs_len):
        print("calling sign_callback for raw key....\n")

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


def get_sign_callback(key):
    if key["type"] == "pkc11":
        return _create_pkcs11_sign_callback(key["key_info"])
    elif key["type"] == "raw":
        return _create_raw_sign_callback(key["key_info"])
    raise exceptions.MutualTLSChannelError(
        "currently only pkcs11 and raw type are supported"
    )

class CustomSigner(object):
    def __init__(self, cert, key):
        if os.name == "nt" and key["type"] == "windows":
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa
            public_key = x509.load_pem_x509_certificate(cert).public_key()
            is_rsa = (isinstance(public_key, rsa.RSAPublicKey))
            print(f"is_rsa is: {is_rsa}")
            key_info = key["key_info"]
            is_local_machine_store = (key_info["provider"] == "local_machine")
            self.offload_signing_ext = offload_signing_ext()
            self.offload_signing_function = self.offload_signing_ext.OffloadSigning
            self.windows_signer_ext = windows_signer_ext()
            self.signer = self.windows_signer_ext.CreateCustomKey(
                ctypes.c_bool(is_rsa),
                ctypes.c_bool(is_local_machine_store),
                ctypes.c_char_p(key_info["store_name"].encode()),
                ctypes.c_char_p(key_info["subject"].encode())
            )
            self.cleanup_func = self.windows_signer_ext.DestroyCustomKey
            atexit.register(self.cleanup)
        else:
            self.offload_signing_ext = offload_signing_ext()
            self.offload_signing_function = self.offload_signing_ext.OffloadSigning
            self.sign_callback = get_sign_callback(key)
            self.signer = self.offload_signing_ext.CreateCustomKey(self.sign_callback)
            self.cleanup_func = self.offload_signing_ext.DestroyCustomKey
            atexit.register(self.cleanup)
    
    def cleanup(self):
        if self.signer:
            print("calling self.offload_signing_ext.DestroyCustomKey")
            self.cleanup_func(self.signer)

def configure_tls_offload(signer, cert, ctx):
    if not signer.offload_signing_function(
        signer.signer,
        ctypes.c_char_p(cert),
        _cast_ssl_ctx_to_void_p(ctx._ctx._context),
    ):
        raise exceptions.MutualTLSChannelError("failed to offload signing")
