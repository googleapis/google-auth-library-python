import faulthandler
import os

faulthandler.enable()

from google.auth.transport.requests import AuthorizedSession
from google.auth import credentials

creds = credentials.AnonymousCredentials()
project = "sijunliu-dca-test"
ca_cert_file = os.path.join(os.getcwd(), "offload_sample", "ca_cert.pem")
rsa_cert_file = os.path.join(os.getcwd(), "offload_sample", "rsa_cert.pem")
rsa_key_file = os.path.join(os.getcwd(), "offload_sample", "rsa_key.pem")
ec_cert_file = os.path.join(os.getcwd(), "offload_sample", "ec_cert.pem")
ec_key_file = os.path.join(os.getcwd(), "offload_sample", "ec_key.pem")

import certifi
def where():
    return ca_cert_file
certifi.where = where

def offload_callback_raw(cert_file, key_file):
    with open(cert_file, "rb") as f:
        cert = f.read()

    key = {
        "type": "raw",
        "key_info": {
            "pem_path": key_file
        } 
    }

    def callback():
        return cert, key
    return callback

def offload_callback_windows_rsa():
    with open(rsa_cert_file, "rb") as f:
        cert = f.read()

    key = {
        "type": "windows_cert_store",
        "key_info": {
            "provider": "current_user",
            "store_name": "MY",
            "subject": "localhost"
        }
    }

    return cert, key

def offload_callback_windows_ec():
    with open(ec_cert_file, "rb") as f:
        cert = f.read()

    key = {
        "type": "windows_cert_store",
        "key_info": {
            "provider": "local_machine",
            "store_name": "MY",
            "subject": "localhost"
        }
    }

    return cert, key

def callback_raw(cert_file, key_file):
    with open(cert_file, "rb") as f:
        cert = f.read()

    with open(key_file, "rb") as f:
        key = f.read()

    def callback():
        return cert, key
    return callback

def callback_daemon_windows_rsa():
    with open(rsa_cert_file, "rb") as f:
        cert = f.read()

    key = {
        "type": "daemon",
        "key_info": {
            "type": "windows_cert_store",
            "key_info": {
                "provider": "local_machine",
                "store_name": "MY",
                "subject": "localhost"
            }
        }
    }

    return cert, key

def run_sample(callback):
    authed_session = AuthorizedSession(creds)
    print("=== before configure_mtls_channel===")
    authed_session.configure_mtls_channel(callback)
    print("=== after configure_mtls_channel===")
    print(authed_session.is_mtls)

    print("=== before calling request===")
    response = authed_session.request('GET', "https://localhost:3000/foo")
    print("=== finished calling request===")
    print(response.status_code)
    print(response.text)


if __name__ == "__main__":
    print("================= using offload + raw rsa key")
    run_sample(offload_callback_raw(rsa_cert_file, rsa_key_file))
    print("================= using offload + raw ec key")
    run_sample(offload_callback_raw(ec_cert_file, ec_key_file))
    print("================= using offload + windows rsa key")
    run_sample(offload_callback_windows_rsa)
    print("================= using offload + windows ec key")
    run_sample(offload_callback_windows_ec)
    print("================= using raw rsa key")
    run_sample(callback_raw(rsa_cert_file, rsa_key_file))
    print("================= using raw ec key")
    run_sample(callback_raw(ec_cert_file, ec_key_file))

    # run_sample(callback_daemon_windows_rsa)