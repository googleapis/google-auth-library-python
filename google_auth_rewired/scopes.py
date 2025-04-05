# google_auth_rewired/scopes.py

"""
🔐 Common Google API OAuth Scopes
These constants help developers avoid copy-pasting long URLs.
"""

# Google Drive
DRIVE_READONLY = "https://www.googleapis.com/auth/drive.readonly"
DRIVE_FULL = "https://www.googleapis.com/auth/drive"

# Google Sheets
SHEETS_READONLY = "https://www.googleapis.com/auth/spreadsheets.readonly"
SHEETS_FULL = "https://www.googleapis.com/auth/spreadsheets"

# Gmail
GMAIL_SEND = "https://www.googleapis.com/auth/gmail.send"
GMAIL_READONLY = "https://www.googleapis.com/auth/gmail.readonly"

# Google Cloud Storage
GCS_FULL = "https://www.googleapis.com/auth/devstorage.full_control"
GCS_READONLY = "https://www.googleapis.com/auth/devstorage.read_only"

# Google Cloud Functions
CLOUD_FUNCTIONS_INVOKE = "https://www.googleapis.com/auth/cloudfunctions.invoke"

# Cloud Run
CLOUD_RUN_INVOKE = "https://www.googleapis.com/auth/cloud-platform"

# Admin SDK
ADMIN_DIRECTORY_READONLY = "https://www.googleapis.com/auth/admin.directory.user.readonly"

# Firestore
FIRESTORE = "https://www.googleapis.com/auth/datastore"
