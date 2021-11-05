import ctypes

callback_type = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
)


def sign_test(data, module_path, token_label, key_label, user_pin=None):
    import pkcs11
    from pkcs11 import KeyType, Mechanism, MGF
    from pkcs11.constants import Attribute
    from pkcs11.constants import ObjectClass
    import pkcs11.util.ec

    lib = pkcs11.lib(module_path)
    token = lib.get_token(token_label=token_label)

    # Open a session on our token
    with token.open(user_pin=user_pin) as session:
        key = session.get_key(label=key_label, object_class=ObjectClass.PRIVATE_KEY)

        digest = session.digest(data, mechanism=Mechanism.SHA256)
        if key.key_type == KeyType.RSA:
            signature = key.sign(
                digest,
                mechanism=Mechanism.RSA_PKCS_PSS,
                mechanism_param=(Mechanism.SHA256, MGF.SHA256, len(digest)),
            )
        else:
            signature = key.sign(digest, mechanism=Mechanism.ECDSA)
            signature = pkcs11.util.ec.encode_ecdsa_signature(signature)

        # reset pkcs11 lib
        pkcs11._lib = None

        print(f"succeeded, signature length: {len(signature)}")

        return signature


def create_sign_callback(module_path, token_label, key_label, user_pin=None):
    def sign_callback(sig, sig_len, tbs, tbs_len):
        import ctypes
        import pkcs11
        from pkcs11 import KeyType, Mechanism, MGF
        from pkcs11.constants import Attribute
        from pkcs11.constants import ObjectClass
        import pkcs11.util.ec
        from cryptography.hazmat.primitives import hashes

        print("calling sign_callback....\n")

        lib = pkcs11.lib(module_path)
        token = lib.get_token(token_label=token_label)

        # Open a session on our token
        with token.open(user_pin=user_pin) as session:
            key = session.get_key(label=key_label, object_class=ObjectClass.PRIVATE_KEY)
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

            print(f"succeeded, signature length: {len(signature)}")

            return 1

    return sign_callback


@callback_type
def sign_callback(sig, sig_len, tbs, tbs_len):
    import ctypes
    import pkcs11
    from pkcs11 import KeyType, Mechanism, MGF
    from pkcs11.constants import Attribute
    from pkcs11.constants import ObjectClass
    import pkcs11.util.ec

    print("calling sign_callback....\n")

    lib = pkcs11.lib("/usr/local/lib/softhsm/libsofthsm2.so")
    token = lib.get_token(token_label="token1")

    # Open a session on our token
    with token.open(user_pin="mynewpin") as session:
        key = session.get_key(label="mtlskey", object_class=ObjectClass.PRIVATE_KEY)
        data = ctypes.string_at(tbs, tbs_len)
        print("data to sign: ")
        print(data)
        digest = session.digest(data, mechanism=Mechanism.SHA256)
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

        print(f"succeeded, signature length: {len(signature)}")
        print(type(signature))

    return 1


callback_type2 = ctypes.CFUNCTYPE(
    ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t
)


def sign(tbs, tbs_len):
    import ctypes
    import pkcs11
    from pkcs11 import KeyType, Mechanism, MGF
    from pkcs11.constants import Attribute
    from pkcs11.constants import ObjectClass
    import pkcs11.util.ec

    print("calling sign_callback....\n")
    data = ctypes.string_at(tbs, tbs_len)

    lib = pkcs11.lib("/usr/local/lib/softhsm/libsofthsm2.so")
    token = lib.get_token(token_label="token1")

    # Open a session on our token
    with token.open(user_pin="mynewpin") as session:
        key = session.get_key(label="rsaclient", object_class=ObjectClass.PRIVATE_KEY)
        digest = session.digest(data, mechanism=Mechanism.SHA256)
        if key.key_type == KeyType.RSA:
            signature = key.sign(
                digest,
                mechanism=Mechanism.RSA_PKCS_PSS,
                mechanism_param=(Mechanism.SHA256, MGF.SHA256, len(digest)),
            )
        else:
            signature = key.sign(digest, mechanism=Mechanism.ECDSA)
            signature = pkcs11.util.ec.encode_ecdsa_signature(signature)

        # reset pkcs11 lib
        pkcs11._lib = None

        print(f"succeeded, signature length: {len(signature)}")

        return signature


if __name__ == "__main__":
    data = b"1234"
    sign_test(
        data, "/usr/local/lib/softhsm/libsofthsm2.so", "token1", "rsaclient", "mynewpin"
    )
    # sign(data, "/usr/lib/x86_64-linux-gnu/pkcs11/libcredentialkit_pkcs11.so.0", "gecc", "gecc")
