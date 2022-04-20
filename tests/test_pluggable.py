# Copyright 2022 Google LLC
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
import pytest  # type: ignore
import subprocess
import pytest_subprocess
from six.moves import http_client
from six.moves import urllib

from google.auth import _helpers
from google.auth import exceptions
from google.auth import identity_pool
from google.auth import pluggable
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
SUBJECT_TOKEN_FIELD_NAME = "access_token"

TOKEN_URL = "https://sts.googleapis.com/v1/token"
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
AUDIENCE = "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"


class TestCredentials(object):
    CREDENTIAL_SOURCE_EXECUTABLE_COMMAND = (
        "/fake/external/excutable --arg1=value1 --arg2=value2"
    )
    CREDENTIAL_SOURCE_EXECUTABLE_OUTPUT_FILE = "fake_output_file"
    CREDENTIAL_SOURCE_EXECUTABLE = {
        "command": CREDENTIAL_SOURCE_EXECUTABLE_COMMAND,
        "timeout_millis": 30000,
        "output_file": CREDENTIAL_SOURCE_EXECUTABLE_OUTPUT_FILE,
    }
    CREDENTIAL_SOURCE = {"executable": CREDENTIAL_SOURCE_EXECUTABLE}
    EXECUTABLE_OIDC_TOKEN = "FAKE_ID_TOKEN"
    EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_ID_TOKEN = {
        "version": 1,
        "success": True,
        "token_type": "urn:ietf:params:oauth:token-type:id_token",
        "id_token": EXECUTABLE_OIDC_TOKEN,
        "expiration_time": 9999999999,
    }
    EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_JWT = {
        "version": 1,
        "success": True,
        "token_type": "urn:ietf:params:oauth:token-type:jwt",
        "id_token": EXECUTABLE_OIDC_TOKEN,
        "expiration_time": 9999999999,
    }
    EXECUTABLE_SAML_TOKEN = "FAKE_SAML_RESPONSE"
    EXECUTABLE_SUCCESSFUL_SAML_RESPONSE = {
        "version": 1,
        "success": True,
        "token_type": "urn:ietf:params:oauth:token-type:saml2",
        "saml_response": EXECUTABLE_SAML_TOKEN,
        "expiration_time": 9999999999,
    }
    EXECUTABLE_FAILED_RESPONSE = {
        "version": 1,
        "success": False,
        "code": "401",
        "message": "Permission denied. Caller not authorized",
    }
    CREDENTIAL_URL = "http://fakeurl.com"

    @classmethod
    def make_mock_response(cls, status, data):
        response = mock.create_autospec(transport.Response, instance=True)
        response.status = status
        if isinstance(data, dict):
            response.data = json.dumps(data).encode("utf-8")
        else:
            response.data = data
        return response

    @classmethod
    def make_mock_request(
        cls, token_status=http_client.OK, token_data=None, *extra_requests
    ):
        responses = []
        responses.append(cls.make_mock_response(token_status, token_data))

        while len(extra_requests) > 0:
            # If service account impersonation is requested, mock the expected response.
            status, data, extra_requests = (
                extra_requests[0],
                extra_requests[1],
                extra_requests[2:],
            )
            responses.append(cls.make_mock_response(status, data))

        request = mock.create_autospec(transport.Request)
        request.side_effect = responses

        return request

    @classmethod
    def assert_credential_request_kwargs(
        cls, request_kwargs, headers, url=CREDENTIAL_URL
    ):
        assert request_kwargs["url"] == url
        assert request_kwargs["method"] == "GET"
        assert request_kwargs["headers"] == headers
        assert request_kwargs.get("body", None) is None

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
        used_scopes=None,
        credential_data=None,
        scopes=None,
        default_scopes=None,
        workforce_pool_user_project=None,
    ):
        """Utility to assert that a credentials are initialized with the expected
        attributes by calling refresh functionality and confirming response matches
        expected one and that the underlying requests were populated with the
        expected parameters.
        """
        # STS token exchange request/response.
        token_response = cls.SUCCESS_RESPONSE.copy()
        token_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if basic_auth_encoding:
            token_headers["Authorization"] = "Basic " + basic_auth_encoding

        if service_account_impersonation_url:
            token_scopes = "https://www.googleapis.com/auth/iam"
        else:
            token_scopes = " ".join(used_scopes or [])

        token_request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "audience": audience,
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": token_scopes,
            "subject_token": subject_token,
            "subject_token_type": subject_token_type,
        }
        if workforce_pool_user_project:
            token_request_data["options"] = urllib.parse.quote(
                json.dumps({"userProject": workforce_pool_user_project})
            )

        if service_account_impersonation_url:
            # Service account impersonation request/response.
            expire_time = (
                _helpers.utcnow().replace(microsecond=0)
                + datetime.timedelta(seconds=3600)
            ).isoformat("T") + "Z"
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
                "scope": used_scopes,
                "lifetime": "3600s",
            }

        # Initialize mock request to handle token retrieval, token exchange and
        # service account impersonation request.
        requests = []
        if credential_data:
            requests.append((http_client.OK, credential_data))

        token_request_index = len(requests)
        requests.append((http_client.OK, token_response))

        if service_account_impersonation_url:
            impersonation_request_index = len(requests)
            requests.append((http_client.OK, impersonation_response))

        request = cls.make_mock_request(*[el for req in requests for el in req])

        credentials.refresh(request)

        assert len(request.call_args_list) == len(requests)
        if credential_data:
            cls.assert_credential_request_kwargs(request.call_args_list[0][1], None)
        # Verify token exchange request parameters.
        cls.assert_token_request_kwargs(
            request.call_args_list[token_request_index][1],
            token_headers,
            token_request_data,
            token_url,
        )
        # Verify service account impersonation request parameters if the request
        # is processed.
        if service_account_impersonation_url:
            cls.assert_impersonation_request_kwargs(
                request.call_args_list[impersonation_request_index][1],
                impersonation_headers,
                impersonation_request_data,
                service_account_impersonation_url,
            )
            assert credentials.token == impersonation_response["accessToken"]
        else:
            assert credentials.token == token_response["access_token"]
        assert credentials.quota_project_id == quota_project_id
        assert credentials.scopes == scopes
        assert credentials.default_scopes == default_scopes

    @classmethod
    def make_pluggable(
        cls,
        audience=AUDIENCE,
        subject_token_type=SUBJECT_TOKEN_TYPE,
        client_id=None,
        client_secret=None,
        quota_project_id=None,
        scopes=None,
        default_scopes=None,
        service_account_impersonation_url=None,
        credential_source=None,
        workforce_pool_user_project=None,
    ):
        return pluggable.Credentials(
            audience=audience,
            subject_token_type=subject_token_type,
            token_url=TOKEN_URL,
            service_account_impersonation_url=service_account_impersonation_url,
            credential_source=credential_source,
            client_id=client_id,
            client_secret=client_secret,
            quota_project_id=quota_project_id,
            scopes=scopes,
            default_scopes=default_scopes,
            workforce_pool_user_project=workforce_pool_user_project,
        )

    @mock.patch.object(pluggable.Credentials, "__init__", return_value=None)
    def test_from_info_full_options(self, mock_init):
        credentials = pluggable.Credentials.from_info(
            {
                "audience": AUDIENCE,
                "subject_token_type": SUBJECT_TOKEN_TYPE,
                "token_url": TOKEN_URL,
                "service_account_impersonation_url": SERVICE_ACCOUNT_IMPERSONATION_URL,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "quota_project_id": QUOTA_PROJECT_ID,
                "credential_source": self.CREDENTIAL_SOURCE,
            }
        )

        # Confirm pluggable.Credentials instantiated with expected attributes.
        assert isinstance(credentials, pluggable.Credentials)
        mock_init.assert_called_once_with(
            audience=AUDIENCE,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=SERVICE_ACCOUNT_IMPERSONATION_URL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            credential_source=self.CREDENTIAL_SOURCE,
            quota_project_id=QUOTA_PROJECT_ID,
            workforce_pool_user_project=None,
        )

    @mock.patch.object(pluggable.Credentials, "__init__", return_value=None)
    def test_from_info_required_options_only(self, mock_init):
        credentials = pluggable.Credentials.from_info(
            {
                "audience": AUDIENCE,
                "subject_token_type": SUBJECT_TOKEN_TYPE,
                "token_url": TOKEN_URL,
                "credential_source": self.CREDENTIAL_SOURCE,
            }
        )

        # Confirm pluggable.Credentials instantiated with expected attributes.
        assert isinstance(credentials, pluggable.Credentials)
        mock_init.assert_called_once_with(
            audience=AUDIENCE,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=None,
            client_id=None,
            client_secret=None,
            credential_source=self.CREDENTIAL_SOURCE,
            quota_project_id=None,
            workforce_pool_user_project=None,
        )

    @mock.patch.object(pluggable.Credentials, "__init__", return_value=None)
    def test_from_file_full_options(self, mock_init, tmpdir):
        info = {
            "audience": AUDIENCE,
            "subject_token_type": SUBJECT_TOKEN_TYPE,
            "token_url": TOKEN_URL,
            "service_account_impersonation_url": SERVICE_ACCOUNT_IMPERSONATION_URL,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "quota_project_id": QUOTA_PROJECT_ID,
            "credential_source": self.CREDENTIAL_SOURCE,
        }
        config_file = tmpdir.join("config.json")
        config_file.write(json.dumps(info))
        credentials = pluggable.Credentials.from_file(str(config_file))

        # Confirm pluggable.Credentials instantiated with expected attributes.
        assert isinstance(credentials, pluggable.Credentials)
        mock_init.assert_called_once_with(
            audience=AUDIENCE,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=SERVICE_ACCOUNT_IMPERSONATION_URL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            credential_source=self.CREDENTIAL_SOURCE,
            quota_project_id=QUOTA_PROJECT_ID,
            workforce_pool_user_project=None,
        )

    @mock.patch.object(pluggable.Credentials, "__init__", return_value=None)
    def test_from_file_required_options_only(self, mock_init, tmpdir):
        info = {
            "audience": AUDIENCE,
            "subject_token_type": SUBJECT_TOKEN_TYPE,
            "token_url": TOKEN_URL,
            "credential_source": self.CREDENTIAL_SOURCE,
        }
        config_file = tmpdir.join("config.json")
        config_file.write(json.dumps(info))
        credentials = pluggable.Credentials.from_file(str(config_file))

        # Confirm pluggable.Credentials instantiated with expected attributes.
        assert isinstance(credentials, pluggable.Credentials)
        mock_init.assert_called_once_with(
            audience=AUDIENCE,
            subject_token_type=SUBJECT_TOKEN_TYPE,
            token_url=TOKEN_URL,
            service_account_impersonation_url=None,
            client_id=None,
            client_secret=None,
            credential_source=self.CREDENTIAL_SOURCE,
            quota_project_id=None,
            workforce_pool_user_project=None,
        )

    def test_constructor_invalid_options(self):
        credential_source = {"unsupported": "value"}

        with pytest.raises(ValueError) as excinfo:
            self.make_pluggable(credential_source=credential_source)

        assert excinfo.match(r"Missing credential_source")

    def test_constructor_invalid_credential_source(self):
        with pytest.raises(ValueError) as excinfo:
            self.make_pluggable(credential_source="non-dict")

        assert excinfo.match(r"Missing credential_source")

    def test_info_with_credential_source(self):
        credentials = self.make_pluggable(
            credential_source=self.CREDENTIAL_SOURCE.copy()
        )

        assert credentials.info == {
            "type": "external_account",
            "audience": AUDIENCE,
            "subject_token_type": SUBJECT_TOKEN_TYPE,
            "token_url": TOKEN_URL,
            "credential_source": self.CREDENTIAL_SOURCE,
        }

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_oidc_id_token(self, fp):
        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(self.EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_ID_TOKEN),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        subject_token = credentials.retrieve_subject_token(None)

        assert subject_token == self.EXECUTABLE_OIDC_TOKEN

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_oidc_jwt(self, fp):
        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(self.EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_JWT),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        subject_token = credentials.retrieve_subject_token(None)

        assert subject_token == self.EXECUTABLE_OIDC_TOKEN

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_saml(self, fp):
        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(self.EXECUTABLE_SUCCESSFUL_SAML_RESPONSE),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        subject_token = credentials.retrieve_subject_token(None)

        assert subject_token == self.EXECUTABLE_SAML_TOKEN

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_failed(self, fp):
        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(self.EXECUTABLE_FAILED_RESPONSE),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        with pytest.raises(exceptions.RefreshError) as excinfo:
            subject_token = credentials.retrieve_subject_token(None)

        assert excinfo.match(
            r"Executable returned unsuccessful response: code: 401, message: Permission denied. Caller not authorized."
        )

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "0"})
    def test_retrieve_subject_token_not_allowd(self, fp):
        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(self.EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_ID_TOKEN),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        with pytest.raises(ValueError) as excinfo:
            subject_token = credentials.retrieve_subject_token(None)

        assert excinfo.match(r"Executables need to be explicitly allowed")

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_invalid_version(self, fp):
        EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_VERSION_2 = {
            "version": 2,
            "success": True,
            "token_type": "urn:ietf:params:oauth:token-type:id_token",
            "id_token": self.EXECUTABLE_OIDC_TOKEN,
            "expiration_time": 9999999999,
        }

        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_VERSION_2),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        with pytest.raises(exceptions.RefreshError) as excinfo:
            subject_token = credentials.retrieve_subject_token(None)

        assert excinfo.match(r"Executable returned unsupported version.")

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_expired_token(self, fp):
        EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_EXPIRED = {
            "version": 1,
            "success": True,
            "token_type": "urn:ietf:params:oauth:token-type:id_token",
            "id_token": self.EXECUTABLE_OIDC_TOKEN,
            "expiration_time": 0,
        }

        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_EXPIRED),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        with pytest.raises(exceptions.RefreshError) as excinfo:
            subject_token = credentials.retrieve_subject_token(None)

        assert excinfo.match(r"The token returned by the executable is expired.")

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_file_cache(self, fp):
        with open(self.CREDENTIAL_SOURCE_EXECUTABLE_OUTPUT_FILE, "w") as output_file:
            json.dump(self.EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_ID_TOKEN, output_file)

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        subject_token = credentials.retrieve_subject_token(None)

        assert subject_token == self.EXECUTABLE_OIDC_TOKEN

        if os.path.exists(self.CREDENTIAL_SOURCE_EXECUTABLE_OUTPUT_FILE):
            os.remove(self.CREDENTIAL_SOURCE_EXECUTABLE_OUTPUT_FILE)

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_unsupported_token_type(self, fp):
        EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE = {
            "version": 1,
            "success": True,
            "token_type": "unsupported_token_type",
            "id_token": self.EXECUTABLE_OIDC_TOKEN,
            "expiration_time": 9999999999,
        }

        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        with pytest.raises(exceptions.RefreshError) as excinfo:
            subject_token = credentials.retrieve_subject_token(None)

        assert excinfo.match(r"Executable returned unsupported token type.")

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_missing_version(self, fp):
        EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE = {
            "success": True,
            "token_type": "urn:ietf:params:oauth:token-type:id_token",
            "id_token": self.EXECUTABLE_OIDC_TOKEN,
            "expiration_time": 9999999999,
        }

        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        with pytest.raises(ValueError) as excinfo:
            subject_token = credentials.retrieve_subject_token(None)

        assert excinfo.match(r"The executable response is missing the version field.")

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_missing_success(self, fp):
        EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE = {
            "version": 1,
            "token_type": "urn:ietf:params:oauth:token-type:id_token",
            "id_token": self.EXECUTABLE_OIDC_TOKEN,
            "expiration_time": 9999999999,
        }

        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        with pytest.raises(ValueError) as excinfo:
            subject_token = credentials.retrieve_subject_token(None)

        assert excinfo.match(r"The executable response is missing the success field.")

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_missing_error_code_message(self, fp):
        EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE = {"version": 1, "success": False}

        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        with pytest.raises(ValueError) as excinfo:
            subject_token = credentials.retrieve_subject_token(None)

        assert excinfo.match(
            r"Error code and message fields are required in the response."
        )

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_missing_expiration_time(self, fp):
        EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE = {
            "version": 1,
            "success": True,
            "token_type": "urn:ietf:params:oauth:token-type:id_token",
            "id_token": self.EXECUTABLE_OIDC_TOKEN,
        }

        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        with pytest.raises(ValueError) as excinfo:
            subject_token = credentials.retrieve_subject_token(None)

        assert excinfo.match(
            r"The executable response is missing the expiration_time field."
        )

    @mock.patch.dict(os.environ, {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"})
    def test_retrieve_subject_token_missing_token_type(self, fp):
        EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE = {
            "version": 1,
            "success": True,
            "id_token": self.EXECUTABLE_OIDC_TOKEN,
            "expiration_time": 9999999999,
        }

        fp.register(
            self.CREDENTIAL_SOURCE_EXECUTABLE_COMMAND.split(),
            stdout=json.dumps(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE),
        )

        credentials = self.make_pluggable(credential_source=self.CREDENTIAL_SOURCE)

        with pytest.raises(ValueError) as excinfo:
            subject_token = credentials.retrieve_subject_token(None)

        assert excinfo.match(
            r"The executable response is missing the token_type field."
        )
