import os
import pytest
from google_auth_rewired.lite import GoogleAuthLite
from google_auth_rewired.scopes import DRIVE_READONLY


@pytest.mark.skipif(not os.path.exists("key.json"), reason="key.json not found")
def test_instance_creation():
    """Sanity check: can we create the class (without actual API call)?"""
    auth = GoogleAuthLite("key.json")
    assert auth.credentials is not None


@pytest.mark.skipif(not os.path.exists("key.json"), reason="key.json not found")
def test_get_access_token():
    """Can we fetch a valid access token?"""
    auth = GoogleAuthLite("key.json")
    token = auth.get_access_token()
    assert isinstance(token, str)
    assert len(token) > 100


@pytest.mark.skipif(not os.path.exists("key.json"), reason="key.json not found")
def test_drive_list_files():
    """Live API call to Google Drive's files endpoint."""
    auth = GoogleAuthLite("key.json", scopes=[DRIVE_READONLY])  # ✅ Add scope
    response = auth.get("https://www.googleapis.com/drive/v3/files")
    assert response.status_code == 200
    print(response.json())
