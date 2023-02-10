import google.auth
import google.auth.transport.requests
import google.oauth2.reauth

cred, _ = google.auth.default()
req = google.auth.transport.requests.Request()

scopes = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/cloud-platform',
    'https://www.googleapis.com/auth/appengine.admin',
    'https://www.googleapis.com/auth/sqlservice.login',  # needed by Cloud SQL
    'https://www.googleapis.com/auth/compute',  # needed by autoscaler
]

rapt_token = google.oauth2.reauth.get_rapt_token(
    req, 
    cred._client_id,
    cred._client_secret,
    cred._refresh_token,
    cred._token_uri,
    scopes=scopes)
print(rapt_token)