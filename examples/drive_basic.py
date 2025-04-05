# examples/drive_basic.py

from google_auth_rewired.lite import GoogleAuthLite
from google_auth_rewired.scopes import DRIVE_READONLY

# 🔐 Path to your downloaded service account key
SERVICE_ACCOUNT_FILE = "key.json"

# 🎯 Drive API endpoint to list files
DRIVE_API_URL = "https://www.googleapis.com/drive/v3/files"

# ✅ Initialize GoogleAuthLite with the correct scope
auth = GoogleAuthLite(
    service_account_file=SERVICE_ACCOUNT_FILE,
    scopes=[DRIVE_READONLY]
)

# 🔁 Make authenticated GET request
response = auth.get(DRIVE_API_URL)

# 📦 Print Drive file metadata
if response.ok:
    files = response.json().get("files", [])
    for file in files:
        print(f"{file.get('name')} ({file.get('id')})")
else:
    print("Error:", response.status_code, response.text)
