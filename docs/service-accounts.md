# 🔐 Setting Up Google Service Accounts (For `google-auth-rewired`)

This doc explains how to set up a Google Cloud **Service Account** and download your `key.json` to test `google-auth-rewired`.

---

## ✅ What You Need

- A free [Google Cloud Platform (GCP)](https://console.cloud.google.com) account
- A project created in GCP
- Basic IAM permissions to create service accounts

---

## 🛠️ Steps

### 1. Go to [Google Cloud Console](https://console.cloud.google.com)

- Select your project (or create a new one)

---

### 2. Enable the Required APIs

Go to **APIs & Services > Library** and enable:

- Google Drive API (for `drive_basic.py`)
- Google Sheets API (for `sheets_read.py`)
- Gmail API (for `gmail_send.py`)
- Google Cloud Storage API (for `gcs_upload.py`)

---

### 3. Create a Service Account

1. Go to **IAM & Admin > Service Accounts**
2. Click `+ Create Service Account`
3. Name it, e.g. `google-auth-rewired-test`
4. Click `Create and Continue`

---

### 4. Grant Permissions (Optional for Testing)

For most tests:
- You can skip assigning roles if you're not accessing protected resources
- If needed, add roles like:
  - `Viewer` for read-only
  - `Storage Admin` for GCS
  - `Drive Admin` for Drive access

---

### 5. Create and Download the Key

1. After the service account is created, click its name
2. Go to the **"Keys" tab**
3. Click **"Add Key" > "Create new key"**
4. Choose `JSON` and click **Create**

> 💾 This will download a file like `key.json` — save it in your project root:
```
C:\Users\yourname\Documents\google-auth-rewired\key.json
```

---

### 6. Add to `.gitignore`

Never commit credentials. Add this to your `.gitignore`:
```
key.json
*.json
```

---

## 🔁 Refreshing Credentials

Service account credentials **auto-refresh** via `google-auth` — no need to manually handle token expiration.

---