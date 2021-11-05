import faulthandler

faulthandler.enable()

from google.auth.transport.requests import AuthorizedSession
import google.auth

credentials, _ = google.auth.default()
project = "sijunliu-dca-test"

def offload_callback_softhsm():
    with open("./cert.pem", "rb") as f:
        cert = f.read()

    # The format is b"engine:<engine_id>:<key_uri>"
    # key_uri is b"pkcs11:token=gecc""
    key = b"offload:pkcs11:softhsm"

    return cert, key

def offload_callback_gecc():
    with open("./gecc_cert.pem", "rb") as f:
        cert = f.read()

    # The format is b"engine:<engine_id>:<key_uri>"
    # key_uri is b"pkcs11:token=gecc""
    key = b"offload:pkcs11:gecc"

    return cert, key

def raw_callback():
    with open("./cert.pem", "rb") as f:
        cert = f.read()

    with open("./key.pem", "rb") as f:
        key = f.read()

    return cert, key

def run_sample(callback):
    authed_session = AuthorizedSession(credentials)
    authed_session.configure_mtls_channel(callback)

    if authed_session.is_mtls:
        response = authed_session.request('GET', f'https://pubsub.mtls.googleapis.com/v1/projects/{project}/topics')
    else:
        response = authed_session.request('GET', f'https://pubsub.googleapis.com/v1/projects/{project}/topics')
    print(response.text)


if __name__ == "__main__":
    #run_sample(raw_callback)
    run_sample(offload_callback_softhsm)
    run_sample(offload_callback_gecc)