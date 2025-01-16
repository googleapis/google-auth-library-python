import pytest
from google.auth.transport.requests import Request
import os
import requests
from google.oauth2 import credentials

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

def test_valid_token_refresh():
    port = os.environ.get("PORT", "5000")  # Get port from environment, default to 5000
    url = f"http://localhost:{port}/oauth2/token200"

    # Create a Credentials object (replace with your actual refresh token)
    creds = credentials.Credentials(
        token=None,  # No initial token
        refresh_token='mock_refresh_token',  # Your refresh token
        token_uri=url,                       # Token endpoint
        client_id='conformance_client',     # Your client ID
        client_secret='conformance_client_secret', # Your client secret
        scopes=['email', 'profile'],  # Your scopes, if needed (might not be for refresh)
    )

    # json_file_path = os.path.join(DATA_DIR, "authorized_user_200.json")
    # creds = credentials.Credentials.from_authorized_user_file(json_file_path)

    # Refresh the credentials to get a new access token
    try:
        creds.refresh(Request()) # Refresh the token
    except Exception as e:
        pytest.fail(f"Token refresh failed: {e}")

    headers = {}
    creds.apply(headers)

    url = f"http://localhost:{port}/oauth2/validate"  # Make sure your server is running on this address and port
    response = requests.post(url, headers=headers)

    assert response.status_code == 200