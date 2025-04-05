# examples/gcs_upload.py

import mimetypes
from google_auth_rewired.lite import GoogleAuthLite
from google_auth_rewired.scopes import GCS_FULL_CONTROL

# 🔐 Path to your service account key
SERVICE_ACCOUNT_FILE = "key.json"

# 📦 File to upload
LOCAL_FILE = "example.txt"
BUCKET_NAME = "your-gcs-bucket-name"
DESTINATION_BLOB_NAME = "uploads/example.txt"

# 📡 GCS Upload Endpoint
GCS_UPLOAD_URL = f"https://storage.googleapis.com/upload/storage/v1/b/{BUCKET_NAME}/o?uploadType=media&name={DESTINATION_BLOB_NAME}"

# 📄 Guess MIME type (fallback to octet-stream)
mime_type, _ = mimetypes.guess_type(LOCAL_FILE)
mime_type = mime_type or "application/octet-stream"

# ✅ Initialize authorized session
auth = GoogleAuthLite(
    service_account_file=SERVICE_ACCOUNT_FILE,
    scopes=[GCS_FULL_CONTROL]
)

# 🚀 Upload the file
with open(LOCAL_FILE, "rb") as f:
    response = auth.post(
        GCS_UPLOAD_URL,
        data=f,
        headers={"Content-Type": mime_type}
    )

# ✅ Success or error
if response.ok:
    print("Upload successful!")
    print("Object metadata:", response.json())
else:
    print("Upload failed:", response.status_code, response.text)
