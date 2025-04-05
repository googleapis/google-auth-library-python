# examples/gmail_send.py

"""
📬 Gmail Send Example — using google_auth_rewired

Requirements to Work:
- Gmail API must be enabled on your Google Cloud project:
    → https://console.cloud.google.com/apis/library/gmail.googleapis.com
- Service account must be delegated domain-wide authority (if sending as a user):
    → https://developers.google.com/admin-sdk/gmail/guides/delegation
- Or: Use OAuth2 flow instead (see oauth_flow.py – WIP)
"""

import base64
from email.mime.text import MIMEText
from google_auth_rewired.lite import GoogleAuthLite
from google_auth_rewired.scopes import GMAIL_SEND

# Initialize auth
auth = GoogleAuthLite(
    service_account_file="key.json",
    scopes=[GMAIL_SEND]
)

def create_message(sender: str, to: str, subject: str, message_text: str) -> dict:
    """Create a base64url encoded email message."""
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw}

# Replace with actual recipient email
sender = "me"  # 'me' means authenticated user
recipient = "someone@example.com"
subject = "Hello from google-auth-rewired 👋"
body = "This is a test email sent via Gmail API and your custom SDK."

msg = create_message(sender, recipient, subject, body)

# Send the email
resp = auth.post(
    url="https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
    json=msg
)

print("Response Status:", resp.status_code)
print("Response Body:", resp.json())
