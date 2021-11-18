import win32crypt
import win32cryptcon
from cryptography.hazmat.primitives import hashes

import faulthandler

faulthandler.enable()


def use_store(data):
    store = win32crypt.CertOpenStore(win32cryptcon.CERT_STORE_PROV_SYSTEM, 0, None, win32cryptcon.CERT_SYSTEM_STORE_CURRENT_USER, "MY")
    print(store)

    issuer = "US, Some-State, MyOrg, localhost"
    cert_contexts = store.CertEnumCertificatesInStore()
    cert = None
    for context in cert_contexts:
        print(win32crypt.CertNameToStr(context.Subject))
        if win32crypt.CertNameToStr(context.Issuer) == issuer:
            cert = context
            print("Found cert")
            break
    print(cert)

    mydict = {"SigningCert": cert, "HashAlgorithm": {"ObjId": "1.2.840.113549.1.1.10", "Parameters":b""}}
    mydict = {"SigningCert": cert, "HashAlgorithm": {"ObjId": win32cryptcon.szOID_RSA_RC2CBC, "Parameters":b""}}

    hash = hashes.Hash(hashes.SHA256())
    hash.update(data)
    digest = hash.finalize()

    sig = win32crypt.CryptSignMessage(mydict, [digest], True)
    print(len(sig))
    print(sig)

def use_raw(data):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric import rsa

    with open("./key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None
        )

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
        signature = private_key.sign(data)
    print(len(signature))
    print(signature)

data = b"123"
use_store(data)
use_raw(data)