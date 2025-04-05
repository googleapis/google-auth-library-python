# 🚀 Getting Started with `google-auth-rewired`

Welcome to the lightweight, execution-first Python auth layer for Google APIs.  
This guide helps you set up and run your first authenticated API call in minutes.

---

## ✅ What This Project Is

`google-auth-rewired` is a **minimal, fast, and focused** Google API authentication wrapper for Python.

No bloat. No enterprise overload. Just what devs actually need:

- 🔐 Load credentials
- 🔁 Auto-refresh tokens
- 🧾 Call APIs with auth headers
- 🪶 All in a clean, importable class

---

## 📦 1. Install the Package

Create a virtual environment and activate it:

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
# OR
source .venv/bin/activate  # Mac/Linux
```

Then install the package + dev tools:

```bash
pip install -e .[dev]
```

---

## 🔐 2. Add Your `key.json`

You’ll need a service account key from GCP.  
Follow the steps in [docs/service-accounts.md](./service-accounts.md) to:

- Create a service account
- Enable APIs (Drive, Sheets, Gmail, etc.)
- Download the key file

Place it in the project root as:

```
google-auth-rewired/
├── key.json  ✅
```

---

## ✨ 3. Run Your First Example

Let’s call the Google Drive API.

```bash
python examples/drive_basic.py
```

Expected output: A list of files from your Google Drive (if access was granted).

---

## 🧠 4. Try Other Examples

These are plug-and-play:

| File | Description |
|------|-------------|
| `examples/drive_basic.py` | Lists files in Google Drive |
| `examples/sheets_read.py` | Reads a spreadsheet |
| `examples/gcs_upload.py` | Uploads a file to Cloud Storage |
| `examples/gmail_send.py` | Sends email via Gmail |

---

## 🧪 5. Run Tests

```bash
pytest
```

Optional: format code with:

```bash
ruff check . --fix
black .
```

---

## 🧭 6. Want More?

Explore these docs next:

- [Service Accounts](./service-accounts.md)
- [OAuth Flow (for user consent)](./oauth-flow.md)
- [Scopes Reference](./scopes-reference.md)

---

## 💥 That’s It

You’re now using Google APIs with power and simplicity.  
Go build something brilliant.