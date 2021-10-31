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
            signature = key.sign(digest, 
                mechanism=Mechanism.RSA_PKCS_PSS,
                mechanism_param=(Mechanism.SHA256, MGF.SHA256, len(digest))
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

        lib = pkcs11.lib(module_path)
        token = lib.get_token(token_label=token_label)

        # Open a session on our token
        with token.open(user_pin=user_pin) as session:
            key = session.get_key(label=key_label, object_class=ObjectClass.PRIVATE_KEY)
            data = ctypes.string_at(tbs, tbs_len)
            digest = session.digest(data, mechanism=Mechanism.SHA256)
            if key.key_type == KeyType.RSA:
                signature = key.sign(digest, 
                    mechanism=Mechanism.RSA_PKCS_PSS,
                    mechanism_param=(Mechanism.SHA256, MGF.SHA256, len(digest))
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


if __name__ == "__main__":
    data = b"1234"
    sign_test(data, "/usr/local/lib/softhsm/libsofthsm2.so", "token1", "rsaclient", "mynewpin")
    #sign(data, "/usr/lib/x86_64-linux-gnu/pkcs11/libcredentialkit_pkcs11.so.0", "gecc", "gecc")