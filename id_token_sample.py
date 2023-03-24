from google.oauth2 import service_account
import google.auth.transport.requests
from google.auth import jwt

cred = service_account.IDTokenCredentials.from_service_account_file(
    '/usr/local/google/home/sijunliu/wks/creds/nondca/srv.json',
    target_audience = "https://pubsub.googleapis.com",
)
cred = cred._with_use_iam_endpoint(True)
req = google.auth.transport.requests.Request()

cred.refresh(req)
print(cred.token)
print(cred.expiry)
print(jwt.decode(cred.token, verify=False))

# cred = service_account.IDTokenCredentials.from_service_account_file(
#     '/usr/local/google/home/sijunliu/wks/creds/nondca/srv.json',
#     target_audience = "https://pubsub.googleapis.com",
#     use_iam_endpoint=False
# )

# cred.refresh(req)
# print(cred.token)
# print(jwt.decode(cred.token, verify=False))