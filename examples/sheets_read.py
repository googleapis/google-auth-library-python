# examples/sheets_read.py

from google_auth_rewired.lite import GoogleAuthLite
from google_auth_rewired.scopes import SHEETS_READONLY

# 🔐 Path to your downloaded service account key
SERVICE_ACCOUNT_FILE = "key.json"

# 📄 Replace with your actual Google Sheets ID and range
SHEET_ID = "your-sheet-id"
RANGE = "Sheet1!A1:D10"

# 📡 Google Sheets API endpoint
SHEETS_API_URL = f"https://sheets.googleapis.com/v4/spreadsheets/{SHEET_ID}/values/{RANGE}"

# ✅ Initialize auth with Sheets read scope
auth = GoogleAuthLite(
    service_account_file=SERVICE_ACCOUNT_FILE,
    scopes=[SHEETS_READONLY]
)

# 🔁 Make GET request to read data from the sheet
response = auth.get(SHEETS_API_URL)

# 🧾 Print result
if response.ok:
    rows = response.json().get("values", [])
    for row in rows:
        print(row)
else:
    print("Error:", response.status_code, response.text)
