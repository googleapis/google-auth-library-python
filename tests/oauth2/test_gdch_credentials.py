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

import mock
import pytest
from six.moves import http_client

from google.auth import exceptions
from google.oauth2 import gdch_credentials


class TestCredentials(object):
    K8S_CA_CERT_PATH = "./k8s_ca_cert.pem"
    K8S_CERT_PATH = "./k8s_cert.pem"
    K8S_KEY_PATH = "./k8s_key.pem"
    K8S_TOKEN_ENDPOINT = "https://k8s_endpoint/v1/token"
    AIS_CA_CERT_PATH = "./ais_ca_cert.pem"
    AIS_TOKEN_ENDPOINT = "https://k8s_endpoint/v1/token"
    AUDIENCE = "audience_foo"
    QUOTA_PROJECT = "project_foo"

    @classmethod
    def make_credentials(cls):
        return gdch_credentials.Credentials(
            cls.K8S_CA_CERT_PATH,
            cls.K8S_CERT_PATH,
            cls.K8S_KEY_PATH,
            cls.K8S_TOKEN_ENDPOINT,
            cls.AIS_CA_CERT_PATH,
            cls.AIS_TOKEN_ENDPOINT,
            cls.AUDIENCE,
            cls.QUOTA_PROJECT,
        )

    def test_with_audience(self):
        creds = self.make_credentials()
        assert creds._audience == self.AUDIENCE

        new_creds = creds.with_audience("bar")
        assert new_creds._audience == "bar"

    def test_with_quota_project(self):
        creds = self.make_credentials()
        assert creds.quota_project_id == self.QUOTA_PROJECT

        new_creds = creds.with_quota_project("project_bar")
        assert new_creds._quota_project_id == "project_bar"

    @mock.patch("google.oauth2._client._token_endpoint_request", autospec=True)
    def test__make_k8s_token_request(self, token_endpoint_request):
        creds = self.make_credentials()
        req = mock.Mock()

        token_endpoint_request.return_value = {
            "status": {
                "token": "k8s_token",
                "expirationTimestamp": "2022-02-22T06:51:46Z",
            }
        }
        assert creds._make_k8s_token_request(req) == "k8s_token"
        token_endpoint_request.assert_called_with(
            req,
            creds._k8s_token_endpoint,
            {},
            None,
            True,
            (creds._k8s_cert_path, creds._k8s_key_path),
            creds._k8s_ca_cert_path,
            http_client.CREATED,
        )

    @mock.patch("google.oauth2._client._token_endpoint_request", autospec=True)
    def test__make_k8s_token_request_no_token(self, token_endpoint_request):
        creds = self.make_credentials()
        req = mock.Mock()

        token_endpoint_request.return_value = {
            "status": {"expirationTimestamp": "2022-02-22T06:51:46Z"}
        }

        with pytest.raises(exceptions.RefreshError) as excinfo:
            creds._make_k8s_token_request(req)
        assert excinfo.match("No access token in k8s token response")

    @mock.patch("google.oauth2._client._token_endpoint_request", autospec=True)
    @mock.patch("google.auth._helpers.utcnow", autospec=True)
    def test__make_ais_token_request(self, utcnow, token_endpoint_request):
        creds = self.make_credentials()
        req = mock.Mock()

        token_endpoint_request.return_value = {
            "access_token": "ais_token",
            "expires_in": 3599,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
        }
        utcnow.return_value = datetime.datetime(2022, 1, 1, 0, 0, 0)

        k8s_token = "k8s_token"
        base64_k8s_token = "azhzX3Rva2Vu"
        ais_token, ais_expiry = creds._make_ais_token_request(k8s_token, req)
        assert ais_token == "ais_token"
        assert ais_expiry == datetime.datetime(2022, 1, 1, 0, 59, 59)
        token_endpoint_request.assert_called_with(
            req,
            creds._ais_token_endpoint,
            {
                "grant_type": gdch_credentials.TOKEN_EXCHANGE_TYPE,
                "audience": creds._audience,
                "requested_token_type": gdch_credentials.ACCESS_TOKEN_TOKEN_TYPE,
                "subject_token": base64_k8s_token,
                "subject_token_type": gdch_credentials.SERVICE_ACCOUNT_TOKEN_TYPE,
            },
            None,
            True,
            None,
            creds._ais_ca_cert_path,
        )

    @mock.patch(
        "google.oauth2.gdch_credentials.Credentials._make_k8s_token_request",
        autospec=True,
    )
    @mock.patch(
        "google.oauth2.gdch_credentials.Credentials._make_ais_token_request",
        autospec=True,
    )
    def test_refresh(self, ais_token_request, k8s_token_request):
        k8s_token_request.return_value = "k8s_token"
        mock_expiry = mock.Mock()
        ais_token_request.return_value = ("ais_token", mock_expiry)

        creds = self.make_credentials()
        req = mock.Mock()
        creds.refresh(req)

        k8s_token_request.assert_called_with(creds, req)
        ais_token_request.assert_called_with(creds, "k8s_token", req)
        assert creds.token == "ais_token"
        assert creds.expiry == mock_expiry

    @mock.patch(
        "google.oauth2.gdch_credentials.Credentials._make_k8s_token_request",
        autospec=True,
    )
    @mock.patch(
        "google.oauth2.gdch_credentials.Credentials._make_ais_token_request",
        autospec=True,
    )
    def test_before_request(self, ais_token_request, k8s_token_request):
        ais_token_request.return_value = ("ais_token", mock.Mock())

        cred = self.make_credentials()
        headers = {}

        cred.before_request(mock.Mock(), "GET", "https://example.com", headers)
        k8s_token_request.assert_called()
        ais_token_request.assert_called()
        assert headers["authorization"] == "Bearer ais_token"
        assert headers["x-goog-user-project"] == "project_foo"
