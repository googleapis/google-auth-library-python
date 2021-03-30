import google.auth
import google.auth.transport.requests
import os

scopes = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/appengine.admin",
    "https://www.googleapis.com/auth/compute",
    "https://www.googleapis.com/auth/accounts.reauth",
]
req = google.auth.transport.requests.Request()
creds, _ = google.auth.default()
creds._scopes = scopes

creds.refresh(req)
creds.refresh(req)
