# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import json

import mock
import pytest
from six.moves import http_client
from six.moves import urllib

from google.auth import _helpers
from google.auth import exceptions
from google.auth import external_account
from google.auth import transport


CLIENT_ID = "username"
CLIENT_SECRET = "password"
# Base64 encoding of "username:password"
BASIC_AUTH_ENCODING = "dXNlcm5hbWU6cGFzc3dvcmQ="


class CredentialsImpl(external_account.Credentials):
    def __init__(
        self,
        audience,
        subject_token_type,
        token_url,
        credential_source,
        client_id=None,
        client_secret=None,
        quota_project_id=None,
        scopes=None,
    ):
        super(CredentialsImpl, self).__init__(
            audience,
            subject_token_type,
            token_url,
            credential_source,
            client_id,
            client_secret,
            quota_project_id,
            scopes,
        )
        self._counter = 0

    def retrieve_subject_token(self, request):
        counter = self._counter
        self._counter += 1
        return "subject_token_{}".format(counter)


class TestCredentials(object):
    TOKEN_URL = "https://sts.googleapis.com/v1/token"
    PROJECT_NUMBER = "123456"
    POOL_ID = "POOL_ID"
    PROVIDER_ID = "PROVIDER_ID"
    AUDIENCE = (
        "//iam.googleapis.com/project/{}"
        "/locations/global/workloadIdentityPools/{}"
        "/providers/{}"
    ).format(PROJECT_NUMBER, POOL_ID, PROVIDER_ID)
    SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
    CREDENTIAL_SOURCE = {"file": "/var/run/secrets/goog.id/token"}
    SUCCESS_RESPONSE = {
        "access_token": "ACCESS_TOKEN",
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "scope1 scope2",
    }
    ERROR_RESPONSE = {
        "error": "invalid_request",
        "error_description": "Invalid subject token",
        "error_uri": "https://tools.ietf.org/html/rfc6749",
    }
    QUOTA_PROJECT_ID = "QUOTA_PROJECT_ID"

    @classmethod
    def make_credentials(
        cls, client_id=None, client_secret=None, quota_project_id=None, scopes=None
    ):
        return CredentialsImpl(
            audience=cls.AUDIENCE,
            subject_token_type=cls.SUBJECT_TOKEN_TYPE,
            token_url=cls.TOKEN_URL,
            credential_source=cls.CREDENTIAL_SOURCE,
            client_id=client_id,
            client_secret=client_secret,
            quota_project_id=quota_project_id,
            scopes=scopes,
        )

    @classmethod
    def make_mock_request(cls, data, status=http_client.OK):
        response = mock.create_autospec(transport.Response, instance=True)
        response.status = status
        response.data = json.dumps(data).encode("utf-8")

        request = mock.create_autospec(transport.Request)
        request.return_value = response

        return request

    @classmethod
    def assert_request_kwargs(cls, request_kwargs, headers, request_data):
        assert request_kwargs["url"] == cls.TOKEN_URL
        assert request_kwargs["method"] == "POST"
        assert request_kwargs["headers"] == headers
        assert request_kwargs["body"] is not None
        body_tuples = urllib.parse.parse_qsl(request_kwargs["body"])
        for (k, v) in body_tuples:
            assert v.decode("utf-8") == request_data[k.decode("utf-8")]
        assert len(body_tuples) == len(request_data.keys())

    def test_default_state(self):
        credentials = self.make_credentials()

        # Not token acquired yet
        assert not credentials.token
        assert not credentials.valid
        # Expiration hasn't been set yet
        assert not credentials.expiry
        assert not credentials.expired
        # Scopes are required
        assert not credentials.scopes
        assert credentials.requires_scopes
        assert not credentials.quota_project_id

    def test_with_scopes(self):
        credentials = self.make_credentials()

        assert not credentials.scopes
        assert credentials.requires_scopes

        scoped_credentials = credentials.with_scopes(["email"])

        assert scoped_credentials.has_scopes(["email"])
        assert not scoped_credentials.requires_scopes

    def test_with_quota_project(self):
        credentials = self.make_credentials()

        assert not credentials.scopes
        assert not credentials.quota_project_id

        quota_project_creds = credentials.with_quota_project("project-foo")

        assert quota_project_creds.quota_project_id == "project-foo"

    @mock.patch("google.auth._helpers.utcnow", return_value=datetime.datetime.min)
    def test_refresh_without_client_auth_success(self, unused_utcnow):
        response = self.SUCCESS_RESPONSE.copy()
        # Test custom expiration to confirm expiry is set correctly.
        response["expires_in"] = 2800
        expected_expiry = datetime.datetime.min + datetime.timedelta(
            seconds=response["expires_in"]
        )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "audience": self.AUDIENCE,
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "subject_token": "subject_token_0",
            "subject_token_type": self.SUBJECT_TOKEN_TYPE,
        }
        request = self.make_mock_request(status=http_client.OK, data=response)
        credentials = self.make_credentials()

        credentials.refresh(request)

        self.assert_request_kwargs(request.call_args.kwargs, headers, request_data)
        assert credentials.valid
        assert credentials.expiry == expected_expiry
        assert not credentials.expired
        assert credentials.token == response["access_token"]

    def test_refresh_without_client_auth_success_explicit_scopes(self):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "audience": self.AUDIENCE,
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": "scope1 scope2",
            "subject_token": "subject_token_0",
            "subject_token_type": self.SUBJECT_TOKEN_TYPE,
        }
        request = self.make_mock_request(
            status=http_client.OK, data=self.SUCCESS_RESPONSE
        )
        credentials = self.make_credentials(scopes=["scope1", "scope2"])

        credentials.refresh(request)

        self.assert_request_kwargs(request.call_args.kwargs, headers, request_data)
        assert credentials.valid
        assert not credentials.expired
        assert credentials.token == self.SUCCESS_RESPONSE["access_token"]
        assert credentials.has_scopes(["scope1", "scope2"])

    def test_refresh_without_client_auth_error(self):
        request = self.make_mock_request(
            status=http_client.BAD_REQUEST, data=self.ERROR_RESPONSE
        )
        credentials = self.make_credentials()

        with pytest.raises(exceptions.OAuthError) as excinfo:
            credentials.refresh(request)

        assert excinfo.match(
            r"Error code invalid_request: Invalid subject token - https://tools.ietf.org/html/rfc6749"
        )
        assert not credentials.expired
        assert credentials.token is None

    def test_refresh_with_client_auth_success(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic {}".format(BASIC_AUTH_ENCODING),
        }
        request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "audience": self.AUDIENCE,
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "subject_token": "subject_token_0",
            "subject_token_type": self.SUBJECT_TOKEN_TYPE,
        }
        request = self.make_mock_request(
            status=http_client.OK, data=self.SUCCESS_RESPONSE
        )
        credentials = self.make_credentials(
            client_id=CLIENT_ID, client_secret=CLIENT_SECRET
        )

        credentials.refresh(request)

        self.assert_request_kwargs(request.call_args.kwargs, headers, request_data)
        assert credentials.valid
        assert not credentials.expired
        assert credentials.token == self.SUCCESS_RESPONSE["access_token"]

    def test_apply_without_quota_project_id(self):
        headers = {}
        request = self.make_mock_request(
            status=http_client.OK, data=self.SUCCESS_RESPONSE
        )
        credentials = self.make_credentials()

        credentials.refresh(request)
        credentials.apply(headers)

        assert headers == {
            "authorization": "Bearer {}".format(self.SUCCESS_RESPONSE["access_token"])
        }

    def test_apply_with_quota_project_id(self):
        headers = {"other": "header-value"}
        request = self.make_mock_request(
            status=http_client.OK, data=self.SUCCESS_RESPONSE
        )
        credentials = self.make_credentials(quota_project_id=self.QUOTA_PROJECT_ID)

        credentials.refresh(request)
        credentials.apply(headers)

        assert headers == {
            "other": "header-value",
            "authorization": "Bearer {}".format(self.SUCCESS_RESPONSE["access_token"]),
            "x-goog-user-project": self.QUOTA_PROJECT_ID,
        }

    def test_before_request(self):
        headers = {"other": "header-value"}
        request = self.make_mock_request(
            status=http_client.OK, data=self.SUCCESS_RESPONSE
        )
        credentials = self.make_credentials()

        # First call should call refresh, setting the token.
        credentials.before_request(request, "POST", "https://example.com/api", headers)

        assert headers == {
            "other": "header-value",
            "authorization": "Bearer {}".format(self.SUCCESS_RESPONSE["access_token"]),
        }

        # Second call shouldn't call refresh.
        credentials.before_request(request, "POST", "https://example.com/api", headers)

        assert headers == {
            "other": "header-value",
            "authorization": "Bearer {}".format(self.SUCCESS_RESPONSE["access_token"]),
        }

    @mock.patch("google.auth._helpers.utcnow")
    def test_before_request_expired(self, utcnow):
        headers = {}
        request = self.make_mock_request(
            status=http_client.OK, data=self.SUCCESS_RESPONSE
        )
        credentials = self.make_credentials()
        credentials.token = "token"
        utcnow.return_value = datetime.datetime.min
        # Set the expiration to one second more than now plus the clock skew
        # accomodation. These credentials should be valid.
        credentials.expiry = (
            datetime.datetime.min + _helpers.CLOCK_SKEW + datetime.timedelta(seconds=1)
        )

        assert credentials.valid
        assert not credentials.expired

        credentials.before_request(request, "POST", "https://example.com/api", headers)

        # Cached token should be used.
        assert headers == {"authorization": "Bearer token"}

        # Next call should simulate 1 second passed.
        utcnow.return_value = datetime.datetime.min + datetime.timedelta(seconds=1)

        assert not credentials.valid
        assert credentials.expired

        credentials.before_request(request, "POST", "https://example.com/api", headers)

        # New token should be retrieved.
        assert headers == {
            "authorization": "Bearer {}".format(self.SUCCESS_RESPONSE["access_token"])
        }
