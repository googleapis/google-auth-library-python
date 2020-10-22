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
import os

import mock
import pytest
from six.moves import http_client
from six.moves import urllib

from google.auth import _helpers
from google.auth import exceptions
from google.auth import identity_pool
from google.auth import transport


CLIENT_ID = "username"
CLIENT_SECRET = "password"
# Base64 encoding of "username:password".
BASIC_AUTH_ENCODING = "dXNlcm5hbWU6cGFzc3dvcmQ="
SERVICE_ACCOUNT_EMAIL = "service-1234@service-name.iam.gserviceaccount.com"
SERVICE_ACCOUNT_IMPERSONATION_URL = (
    "https://us-east1-iamcredentials.googleapis.com/v1/projects/-"
    + "/serviceAccounts/{}:generateAccessToken".format(SERVICE_ACCOUNT_EMAIL)
)
QUOTA_PROJECT_ID = "QUOTA_PROJECT_ID"
SCOPES = ["scope1", "scope2"]
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
SUBJECT_TOKEN_TEXT_FILE = os.path.join(DATA_DIR, "external_subject_token.txt")
SUBJECT_TOKEN_JSON_FILE = os.path.join(DATA_DIR, "external_subject_token.json")
SUBJECT_TOKEN_FIELD_NAME = "access_token"

with open(SUBJECT_TOKEN_TEXT_FILE) as fh:
    TEXT_FILE_SUBJECT_TOKEN = fh.read()

with open(SUBJECT_TOKEN_JSON_FILE) as fh:
    content = json.load(fh)
    JSON_FILE_SUBJECT_TOKEN = content.get(SUBJECT_TOKEN_FIELD_NAME)

TOKEN_URL = "https://sts.googleapis.com/v1/token"
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
AUDIENCE = "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"


class TestCredentials(object):
    CREDENTIAL_SOURCE_TEXT = {"file": SUBJECT_TOKEN_TEXT_FILE}
    CREDENTIAL_SOURCE_JSON = {
        "file": SUBJECT_TOKEN_JSON_FILE,
        "format": {"type": "json", "subject_token_field_name": "access_token"},
    }
    SUCCESS_RESPONSE = {
        "access_token": "ACCESS_TOKEN",
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": " ".join(SCOPES),
    }

    @classmethod
    def make_mock_request(
        cls,
        token_status=http_client.OK,
        token_data=None,
        impersonation_status=None,
        impersonation_data=None,
    ):
        responses = []
        # STS token exchange request.
        token_response = mock.create_autospec(transport.Response, instance=True)
        token_response.status = token_status
        token_response.data = json.dumps(token_data).encode("utf-8")
        responses.append(token_response)

        # If service account impersonation is requested, mock the expected response.
        if impersonation_status:
            impersonation_response = mock.create_autospec(
                transport.Response, instance=True
            )
            impersonation_response.status = impersonation_status
            impersonation_response.data = json.dumps(impersonation_data).encode("utf-8")
            responses.append(impersonation_response)

        request = mock.create_autospec(transport.Request)
        request.side_effect = responses

        return request

    @classmethod
    def assert_token_request_kwargs(
        cls, request_kwargs, headers, request_data, token_url=TOKEN_URL
    ):
        assert request_kwargs["url"] == token_url
        assert request_kwargs["method"] == "POST"
        assert request_kwargs["headers"] == headers
        assert request_kwargs["body"] is not None
        body_tuples = urllib.parse.parse_qsl(request_kwargs["body"])
        assert len(body_tuples) == len(request_data.keys())
        for (k, v) in body_tuples:
            assert v.decode("utf-8") == request_data[k.decode("utf-8")]

    @classmethod
    def assert_impersonation_request_kwargs(
        cls,
        request_kwargs,
        headers,
        request_data,
        service_account_impersonation_url=SERVICE_ACCOUNT_IMPERSONATION_URL,
    ):
        assert request_kwargs["url"] == service_account_impersonation_url
        assert request_kwargs["method"] == "POST"
        assert request_kwargs["headers"] == headers
        assert request_kwargs["body"] is not None
        body_json = json.loads(request_kwargs["body"].decode("utf-8"))
        assert body_json == request_data

    @classmethod
    def assert_underlying_credentials_refresh(
        cls,
        credentials,
        audience,
        subject_token,
        subject_token_type,
        token_url,
        service_account_impersonation_url=None,
        basic_auth_encoding=None,
        quota_project_id=None,
        scopes=None,
    ):
        """Utility to assert that a credentials are initialized with the expected
        attributes by calling refresh functionality and confirming response matches
        expected one and that the underlying requests were populated with the
        expected parameters.
        """

        expire_time = (
            _helpers.utcnow().replace(microsecond=0) + datetime.timedelta(seconds=3600)
        ).isoformat("T") + "Z"
        # STS token exchange request/response.
        token_response = cls.SUCCESS_RESPONSE.copy()

        token_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if basic_auth_encoding:
            token_headers["Authorization"] = "Basic " + basic_auth_encoding
        if service_account_impersonation_url:
            token_scopes = "https://www.googleapis.com/auth/iam"
            impersonation_status = http_client.OK
            total_requests = 2
        else:
            token_scopes = " ".join(scopes or [])
            impersonation_status = None
            total_requests = 1
        token_request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "audience": audience,
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": token_scopes,
            "subject_token": subject_token,
            "subject_token_type": subject_token_type,
        }
        # Service account impersonation request/response.
        impersonation_response = {
            "accessToken": "SA_ACCESS_TOKEN",
            "expireTime": expire_time,
        }
        impersonation_headers = {
            "Content-Type": "application/json",
            "authorization": "Bearer {}".format(token_response["access_token"]),
        }
        impersonation_request_data = {
            "delegates": None,
            "scope": scopes,
            "lifetime": "3600s",
        }
        # Initialize mock request to handle token exchange and service account
        # impersonation request.
        request = cls.make_mock_request(
            token_status=http_client.OK,
            token_data=token_response,
            impersonation_status=impersonation_status,
            impersonation_data=impersonation_response,
        )

        credentials.refresh(request)

        assert len(request.call_args_list) == total_requests
        # Verify token exchange request parameters.
        cls.assert_token_request_kwargs(
            request.call_args_list[0].kwargs,
            token_headers,
            token_request_data,
            token_url,
        )
        # Verify service account impersonation request parameters if the request
        # is processed.
        if impersonation_status:
            cls.assert_impersonation_request_kwargs(
                request.call_args_list[1].kwargs,
                impersonation_headers,
                impersonation_request_data,
                service_account_impersonation_url,
            )
            assert credentials.token == impersonation_response["accessToken"]
        else:
            assert credentials.token == token_response["access_token"]
        assert credentials.quota_project_id == quota_project_id
        assert credentials.scopes == scopes

    @classmethod
    def make_credentials(
        cls,
        client_id=None,
        client_secret=None,
        quota_project_id=None,
        scopes=None,
        service_account_impersonation_url=None,
        credential_source=None,
    ):
        return identity_pool.Credentials(
            audience=AUDIENCE,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=service_account_impersonation_url,
            credential_source=credential_source,
            client_id=client_id,
            client_secret=client_secret,
            quota_project_id=quota_project_id,
            scopes=scopes,
        )

    @mock.patch.object(identity_pool.Credentials, "__init__", return_value=None)
    def test_from_info_full_options(self, mock_init):
        credentials = identity_pool.Credentials.from_info(
            {
                "audience": AUDIENCE,
                "subject_token_type": SUBJECT_TOKEN_TYPE,
                "token_url": TOKEN_URL,
                "service_account_impersonation_url": SERVICE_ACCOUNT_IMPERSONATION_URL,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "quota_project_id": QUOTA_PROJECT_ID,
                "credential_source": self.CREDENTIAL_SOURCE_TEXT,
            }
        )

        # Confirm identity_pool.Credentials instantiated with expected attributes.
        assert isinstance(credentials, identity_pool.Credentials)
        mock_init.assert_called_once_with(
            audience=AUDIENCE,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=SERVICE_ACCOUNT_IMPERSONATION_URL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            credential_source=self.CREDENTIAL_SOURCE_TEXT,
            quota_project_id=QUOTA_PROJECT_ID,
        )

    @mock.patch.object(identity_pool.Credentials, "__init__", return_value=None)
    def test_from_info_required_options_only(self, mock_init):
        credentials = identity_pool.Credentials.from_info(
            {
                "audience": AUDIENCE,
                "subject_token_type": SUBJECT_TOKEN_TYPE,
                "token_url": TOKEN_URL,
                "credential_source": self.CREDENTIAL_SOURCE_TEXT,
            }
        )

        # Confirm identity_pool.Credentials instantiated with expected attributes.
        assert isinstance(credentials, identity_pool.Credentials)
        mock_init.assert_called_once_with(
            audience=AUDIENCE,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=None,
            client_id=None,
            client_secret=None,
            credential_source=self.CREDENTIAL_SOURCE_TEXT,
            quota_project_id=None,
        )

    @mock.patch.object(identity_pool.Credentials, "__init__", return_value=None)
    def test_from_file_full_options(self, mock_init, tmpdir):
        info = {
            "audience": AUDIENCE,
            "subject_token_type": SUBJECT_TOKEN_TYPE,
            "token_url": TOKEN_URL,
            "service_account_impersonation_url": SERVICE_ACCOUNT_IMPERSONATION_URL,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "quota_project_id": QUOTA_PROJECT_ID,
            "credential_source": self.CREDENTIAL_SOURCE_TEXT,
        }
        config_file = tmpdir.join("config.json")
        config_file.write(json.dumps(info))
        credentials = identity_pool.Credentials.from_file(str(config_file))

        # Confirm identity_pool.Credentials instantiated with expected attributes.
        assert isinstance(credentials, identity_pool.Credentials)
        mock_init.assert_called_once_with(
            audience=AUDIENCE,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=SERVICE_ACCOUNT_IMPERSONATION_URL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            credential_source=self.CREDENTIAL_SOURCE_TEXT,
            quota_project_id=QUOTA_PROJECT_ID,
        )

    @mock.patch.object(identity_pool.Credentials, "__init__", return_value=None)
    def test_from_file_required_options_only(self, mock_init, tmpdir):
        info = {
            "audience": AUDIENCE,
            "subject_token_type": SUBJECT_TOKEN_TYPE,
            "token_url": TOKEN_URL,
            "credential_source": self.CREDENTIAL_SOURCE_TEXT,
        }
        config_file = tmpdir.join("config.json")
        config_file.write(json.dumps(info))
        credentials = identity_pool.Credentials.from_file(str(config_file))

        # Confirm identity_pool.Credentials instantiated with expected attributes.
        assert isinstance(credentials, identity_pool.Credentials)
        mock_init.assert_called_once_with(
            audience=AUDIENCE,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=None,
            client_id=None,
            client_secret=None,
            credential_source=self.CREDENTIAL_SOURCE_TEXT,
            quota_project_id=None,
        )

    def test_constructor_invalid_options(self):
        credential_source = {"unsupported": "value"}

        with pytest.raises(exceptions.GoogleAuthError) as excinfo:
            self.make_credentials(credential_source=credential_source)

        assert excinfo.match(r"Missing credential_source file")

    def test_constructor_invalid_credential_source(self):
        with pytest.raises(exceptions.GoogleAuthError) as excinfo:
            self.make_credentials(credential_source="non-dict")

        assert excinfo.match(r"Missing credential_source file")

    def test_constructor_invalid_credential_source_format_type(self):
        credential_source = {"format": {"type": "xml"}}

        with pytest.raises(exceptions.GoogleAuthError) as excinfo:
            self.make_credentials(credential_source=credential_source)

        assert excinfo.match(r"Invalid credential_source format 'xml'")

    def test_constructor_missing_subject_token_field_name(self):
        credential_source = {"format": {"type": "json"}}

        with pytest.raises(exceptions.GoogleAuthError) as excinfo:
            self.make_credentials(credential_source=credential_source)

        assert excinfo.match(
            r"Missing subject_token_field_name for JSON credential_source format"
        )

    def test_retrieve_subject_token_missing_subject_token(self, tmpdir):
        # Provide empty text file.
        empty_file = tmpdir.join("empty.txt")
        empty_file.write("")
        credential_source = {"file": str(empty_file)}
        credentials = self.make_credentials(credential_source=credential_source)

        with pytest.raises(exceptions.RefreshError) as excinfo:
            credentials.retrieve_subject_token(None)

        assert excinfo.match(r"Missing subject_token in the credential_source file")

    def test_retrieve_subject_token_text_file(self):
        credentials = self.make_credentials(
            credential_source=self.CREDENTIAL_SOURCE_TEXT
        )

        subject_token = credentials.retrieve_subject_token(None)

        assert subject_token == TEXT_FILE_SUBJECT_TOKEN

    def test_retrieve_subject_token_json_file(self):
        credentials = self.make_credentials(
            credential_source=self.CREDENTIAL_SOURCE_JSON
        )

        subject_token = credentials.retrieve_subject_token(None)

        assert subject_token == JSON_FILE_SUBJECT_TOKEN

    def test_retrieve_subject_token_json_file_invalid_field_name(self):
        credential_source = {
            "file": SUBJECT_TOKEN_JSON_FILE,
            "format": {"type": "json", "subject_token_field_name": "not_found"},
        }
        credentials = self.make_credentials(credential_source=credential_source)

        with pytest.raises(exceptions.RefreshError) as excinfo:
            credentials.retrieve_subject_token(None)

        assert excinfo.match(
            "Unable to parse subject_token from JSON file '{}' using key '{}'".format(
                SUBJECT_TOKEN_JSON_FILE, "not_found"
            )
        )

    def test_retrieve_subject_token_invalid_json(self, tmpdir):
        # Provide JSON file. This should result in JSON parsing error.
        invalid_json_file = tmpdir.join("invalid.json")
        invalid_json_file.write("{")
        credential_source = {
            "file": str(invalid_json_file),
            "format": {"type": "json", "subject_token_field_name": "access_token"},
        }
        credentials = self.make_credentials(credential_source=credential_source)

        with pytest.raises(exceptions.RefreshError) as excinfo:
            credentials.retrieve_subject_token(None)

        assert excinfo.match(
            "Unable to parse subject_token from JSON file '{}' using key '{}'".format(
                str(invalid_json_file), "access_token"
            )
        )

    def test_retrieve_subject_token_file_not_found(self):
        credential_source = {"file": "./not_found.txt"}
        credentials = self.make_credentials(credential_source=credential_source)

        with pytest.raises(exceptions.RefreshError) as excinfo:
            credentials.retrieve_subject_token(None)

        assert excinfo.match(r"File './not_found.txt' was not found")

    def test_refresh_text_file_success_without_impersonation(self):
        credentials = self.make_credentials(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            # Test with text format type.
            credential_source=self.CREDENTIAL_SOURCE_TEXT,
            scopes=SCOPES,
        )

        self.assert_underlying_credentials_refresh(
            credentials=credentials,
            audience=AUDIENCE,
            subject_token=TEXT_FILE_SUBJECT_TOKEN,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=None,
            basic_auth_encoding=BASIC_AUTH_ENCODING,
            quota_project_id=None,
            scopes=SCOPES,
        )

    def test_refresh_text_file_success_with_impersonation(self):
        # Initialize credentials with service account impersonation and basic auth.
        credentials = self.make_credentials(
            # Test with text format type.
            credential_source=self.CREDENTIAL_SOURCE_TEXT,
            service_account_impersonation_url=SERVICE_ACCOUNT_IMPERSONATION_URL,
            scopes=SCOPES,
        )

        self.assert_underlying_credentials_refresh(
            credentials=credentials,
            audience=AUDIENCE,
            subject_token=TEXT_FILE_SUBJECT_TOKEN,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=SERVICE_ACCOUNT_IMPERSONATION_URL,
            basic_auth_encoding=None,
            quota_project_id=None,
            scopes=SCOPES,
        )

    def test_refresh_json_file_success_without_impersonation(self):
        credentials = self.make_credentials(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            # Test with JSON format type.
            credential_source=self.CREDENTIAL_SOURCE_JSON,
            scopes=SCOPES,
        )

        self.assert_underlying_credentials_refresh(
            credentials=credentials,
            audience=AUDIENCE,
            subject_token=JSON_FILE_SUBJECT_TOKEN,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=None,
            basic_auth_encoding=BASIC_AUTH_ENCODING,
            quota_project_id=None,
            scopes=SCOPES,
        )

    def test_refresh_json_file_success_with_impersonation(self):
        # Initialize credentials with service account impersonation and basic auth.
        credentials = self.make_credentials(
            # Test with JSON format type.
            credential_source=self.CREDENTIAL_SOURCE_JSON,
            service_account_impersonation_url=SERVICE_ACCOUNT_IMPERSONATION_URL,
            scopes=SCOPES,
        )

        self.assert_underlying_credentials_refresh(
            credentials=credentials,
            audience=AUDIENCE,
            subject_token=JSON_FILE_SUBJECT_TOKEN,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=SERVICE_ACCOUNT_IMPERSONATION_URL,
            basic_auth_encoding=None,
            quota_project_id=None,
            scopes=SCOPES,
        )

    def test_refresh_with_retrieve_subject_token_error(self):
        credential_source = {
            "file": SUBJECT_TOKEN_JSON_FILE,
            "format": {"type": "json", "subject_token_field_name": "not_found"},
        }
        credentials = self.make_credentials(credential_source=credential_source)

        with pytest.raises(exceptions.RefreshError) as excinfo:
            credentials.refresh(None)

        assert excinfo.match(
            "Unable to parse subject_token from JSON file '{}' using key '{}'".format(
                SUBJECT_TOKEN_JSON_FILE, "not_found"
            )
        )
