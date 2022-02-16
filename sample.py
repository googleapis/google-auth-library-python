import faulthandler
import os

faulthandler.enable()

from google.auth.transport.requests import AuthorizedSession
from google.auth import credentials

creds = credentials.AnonymousCredentials()

cert_file = os.path.join(os.getcwd(), "cert.pem")

import certifi
def where():
    return cert_file
certifi.where = where

def run_sample(callback):
    authed_session = AuthorizedSession(creds)
    authed_session.configure_mtls_channel(callback)
 
    response = authed_session.request('GET', "https://localhost:3000/foo")
    print(response.status_code)
    print(response.text)

def callback_windows():
    key = {
        "type": "windows_cert_store",
        "key_info": {
            "provider": "local_machine",
            "store_name": "MY",
            "subject": "localhost"
        }
    }

    return None, key

for i in range(2): run_sample(callback_windows)
