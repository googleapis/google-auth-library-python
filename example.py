from google.oauth2 import gdch_credentials
import google.auth.crypt


path = "/usr/local/google/home/sijunliu/wks/creds/gdch_384.json"
cred = gdch_credentials.ServiceAccountCredentials.from_service_account_file(path)

message = "abc"

# Sign the message
signature = cred._signer.sign(message)

# Verify the signature
verifier = google.auth.crypt.EsVerifier(cred._signer._key.public_key())
print(verifier.verify(message, signature))