import unittest
from unittest.mock import MagicMock, patch
import json
import http.client as http_client
from google.auth import exceptions
from google.auth import impersonated_credentials
from google.auth import credentials

class TestIDTokenCredentialsFix(unittest.TestCase):
    def test_refresh_200_missing_token_raises_refresh_error(self):
        # Setup
        mock_source_creds = MagicMock(spec=credentials.Credentials)
        mock_target_creds = MagicMock(spec=impersonated_credentials.Credentials)
        mock_target_creds._source_credentials = mock_source_creds
        mock_target_creds.universe_domain = "googleapis.com"
        mock_target_creds.signer_email = "signer@example.com"
        mock_target_creds._delegates = []

        creds = impersonated_credentials.IDTokenCredentials(
            target_credentials=mock_target_creds,
            target_audience="aud",
            include_email=True
        )

        # Mock AuthorizedSession
        with patch("google.auth.transport.requests.AuthorizedSession") as MockSession:
            mock_session_instance = MockSession.return_value

            # Mock Response 200 but missing token
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"not_token": "something"}
            mock_session_instance.post.return_value = mock_response

            request = MagicMock()

            # Action & Assert
            # Before the fix, this raised KeyError. Now it should raise RefreshError.
            with self.assertRaises(exceptions.RefreshError) as cm:
                creds.refresh(request)

            self.assertIn("No ID token in response", str(cm.exception))

    def test_refresh_403_raises_refresh_error(self):
        # Setup (same as before to ensure no regression)
        mock_source_creds = MagicMock(spec=credentials.Credentials)
        mock_target_creds = MagicMock(spec=impersonated_credentials.Credentials)
        mock_target_creds._source_credentials = mock_source_creds
        mock_target_creds.universe_domain = "googleapis.com"
        mock_target_creds.signer_email = "signer@example.com"
        mock_target_creds._delegates = []

        creds = impersonated_credentials.IDTokenCredentials(
            target_credentials=mock_target_creds,
            target_audience="aud",
            include_email=True
        )

        # Mock AuthorizedSession
        with patch("google.auth.transport.requests.AuthorizedSession") as MockSession:
            mock_session_instance = MockSession.return_value

            # Mock Response 403
            mock_response = MagicMock()
            mock_response.status_code = 403
            mock_response.json.return_value = {"error": "Permission denied"}
            mock_session_instance.post.return_value = mock_response

            request = MagicMock()

            with self.assertRaises(exceptions.RefreshError) as cm:
                creds.refresh(request)

            self.assertIn("Error getting ID token", str(cm.exception))

if __name__ == "__main__":
    unittest.main()
