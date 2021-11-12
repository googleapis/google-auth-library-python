import cffi
import ctypes
import os
import re

from google.auth import exceptions


def _cast_ssl_ctx_to_void_p(ssl_ctx):
    return ctypes.cast(int(cffi.FFI().cast("intptr_t", ssl_ctx)), ctypes.c_void_p)


def offload_signing_function():
    tls_offload_ext = None
    root_path = os.path.join(os.path.dirname(__file__), "../../../")
    for filename in os.listdir(root_path):
        if re.match("tls_offload_ext*", filename):
            tls_offload_ext = ctypes.CDLL(os.path.join(root_path, filename))
    if not tls_offload_ext:
        raise exceptions.MutualTLSChannelError(
            "tls_offload_ext shared library is not found"
        )
    return tls_offload_ext.OffloadSigning


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


def get_sign_callback(key):
    if key["type"] == "pkc11":
        return _create_pkcs11_sign_callback(key["info"])
    raise exceptions.MutualTLSChannelError("currently only pkcs11 type is supported")
