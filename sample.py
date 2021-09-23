"""
export GOOGLE_AUTH_BUILD_PKCS11=1

export GOOGLE_AUTH_PKCS11_MODULE_PATH=/usr/local/lib/softhsm/libsofthsm2.so
export GOOGLE_AUTH_PKCS11_SO_PATH=/usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so

export GOOGLE_API_USE_CLIENT_CERTIFICATE=true
export SOFTHSM2_CONF=./../mtls-http-local-server-test/softhsm.conf
"""

from google.auth import credentials
import google.auth.transport.requests

cred = credentials.AnonymousCredentials()
req = google.auth.transport.requests.Request()
s = google.auth.transport.requests.AuthorizedSession(cred)

def callback():
    with open("./ec-client-cert.pem", "rb") as f:
        cert = f.read()
        return cert, b"engine:pkcs11:pkcs11:token=token1;object=ecclient;pin-value=mynewpin"

import certifi
certifi.where = lambda :"./rsa-server-cert.pem"

s.configure_mtls_channel(callback)
res = s.get("https://localhost:12345")
print(res.status_code)
res = s.get("https://localhost:12345")
print(res.status_code)