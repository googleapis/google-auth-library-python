import datetime
import json

import mock
import pytest  # type: ignore
from six.moves import http_client

from google.auth import exceptions
from google.auth import external_account_authorized_user
from google.auth import transport


class TestCredentials(object):
    TOKEN_URL = "https://sts.googleapis.com/v1/token"
    TOKEN_INFO_URL = "https://sts.googleapis.com/v1/introspect"
    REVOKE_URL = "https://sts.googleapis.com/v1/revoke"
    PROJECT_NUMBER = "123456"
    POOL_ID = "POOL_ID"
    PROVIDER_ID = "PROVIDER_ID"
    AUDIENCE = (
        "//iam.googleapis.com/projects/{}"
        "/locations/global/workloadIdentityPools/{}"
        "/providers/{}"
    ).format(PROJECT_NUMBER, POOL_ID, PROVIDER_ID)
    REFRESH_TOKEN = "refreshtoken"
    ACCESS_TOKEN = "ACCESS_TOKEN"
    CLIENT_ID = "username"
    CLIENT_SECRET = "password"
    # Base64 encoding of "username:password".
    BASIC_AUTH_ENCODING = "dXNlcm5hbWU6cGFzc3dvcmQ="

    @classmethod
    def make_credentials(
        cls,
        audience=None,
        refresh_token=None,
        token_url=None,
        token_info_url=None,
        client_id=None,
        client_secret=None,
        revoke_url=None,
        quota_project_id=None,
    ):
        return external_account_authorized_user.Credentials(
            audience=(audience or cls.AUDIENCE),
            refresh_token=(refresh_token or cls.REFRESH_TOKEN),
            token_url=(token_url or cls.TOKEN_URL),
            token_info_url=(token_info_url or cls.TOKEN_INFO_URL),
            client_id=(client_id or cls.CLIENT_ID),
            client_secret=(client_secret or cls.CLIENT_SECRET),
            revoke_url=revoke_url,
            quota_project_id=quota_project_id,
        )

    @classmethod
    def make_mock_request(cls, status=http_client.OK, data=None):
        # STS token exchange request.
        token_response = mock.create_autospec(transport.Response, instance=True)
        token_response.status = status
        token_response.data = json.dumps(data).encode("utf-8")
        responses = [token_response]

        request = mock.create_autospec(transport.Request)
        request.side_effect = responses

        return request

    def test_default_state(self):
        creds = self.make_credentials()

        assert not creds.expiry
        assert not creds.expired
        assert not creds.token
        assert not creds.valid
        assert not creds.requires_scopes

    def test_refresh_auth_success(self):
        request = self.make_mock_request(
            status=http_client.OK,
            data={"access_token": self.ACCESS_TOKEN, "expires_in": 3600},
        )
        creds = self.make_credentials()

        creds.refresh(request)

        assert creds.expiry
        assert not creds.expired
        assert creds.token == self.ACCESS_TOKEN
        assert creds.valid
        assert not creds.requires_scopes

        request.assert_called_once_with(
            url=self.TOKEN_URL,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": "Basic " + self.BASIC_AUTH_ENCODING,
            },
            body=bytes(
                "grant_type=refresh_token&refresh_token=" + self.REFRESH_TOKEN, "UTF-8"
            ),
        )

    def test_refresh_auth_failure(self):
        request = self.make_mock_request(
            status=http_client.BAD_REQUEST, data={"error": "XXXXXX"}
        )
        creds = self.make_credentials()

        with pytest.raises(exceptions.OAuthError):
            creds.refresh(request)

        assert not creds.expiry
        assert not creds.expired
        assert not creds.token
        assert not creds.valid
        assert not creds.requires_scopes

        request.assert_called_once_with(
            url=self.TOKEN_URL,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": "Basic " + self.BASIC_AUTH_ENCODING,
            },
            body=bytes(
                "grant_type=refresh_token&refresh_token=" + self.REFRESH_TOKEN, "UTF-8"
            ),
        )
