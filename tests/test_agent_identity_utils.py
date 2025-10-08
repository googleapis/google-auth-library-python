# Copyright 2025 Google LLC
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

import json

import mock
import pytest

from google.auth import _agent_identity_utils
from google.auth import environment_vars
from google.auth import exceptions

# A mock PEM-encoded certificate without an Agent Identity SPIFFE ID.
NON_AGENT_IDENTITY_CERT_BYTES = (
    b"-----BEGIN CERTIFICATE-----\n"
    b"MIIDIzCCAgugAwIBAgIJAMfISuBQ5m+5MA0GCSqGSIb3DQEBBQUAMBUxEzARBgNV\n"
    b"BAMTCnVuaXQtdGVzdHMwHhcNMTExMjA2MTYyNjAyWhcNMjExMjAzMTYyNjAyWjAV\n"
    b"MRMwEQYDVQQDEwp1bml0LXRlc3RzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n"
    b"CgKCAQEA4ej0p7bQ7L/r4rVGUz9RN4VQWoej1Bg1mYWIDYslvKrk1gpj7wZgkdmM\n"
    b"7oVK2OfgrSj/FCTkInKPqaCR0gD7K80q+mLBrN3PUkDrJQZpvRZIff3/xmVU1Wer\n"
    b"uQLFJjnFb2dqu0s/FY/2kWiJtBCakXvXEOb7zfbINuayL+MSsCGSdVYsSliS5qQp\n"
    b"gyDap+8b5fpXZVJkq92hrcNtbkg7hCYUJczt8n9hcCTJCfUpApvaFQ18pe+zpyl4\n"
    b"+WzkP66I28hniMQyUlA1hBiskT7qiouq0m8IOodhv2fagSZKjOTTU2xkSBc//fy3\n"
    b"ZpsL7WqgsZS7Q+0VRK8gKfqkxg5OYQIDAQABo3YwdDAdBgNVHQ4EFgQU2RQ8yO+O\n"
    b"gN8oVW2SW7RLrfYd9jEwRQYDVR0jBD4wPIAU2RQ8yO+OgN8oVW2SW7RLrfYd9jGh\n"
    b"GaQXMBUxEzARBgNVBAMTCnVuaXQtdGVzdHOCCQDHyErgUOZvuTAMBgNVHRMEBTAD\n"
    b"AQH/MA0GCSqGSIb3DQEBBQUAA4IBAQBRv+M/6+FiVu7KXNjFI5pSN17OcW5QUtPr\n"
    b"odJMlWrJBtynn/TA1oJlYu3yV5clc/71Vr/AxuX5xGP+IXL32YDF9lTUJXG/uUGk\n"
    b"+JETpKmQviPbRsvzYhz4pf6ZIOZMc3/GIcNq92ECbseGO+yAgyWUVKMmZM0HqXC9\n"
    b"ovNslqe0M8C1sLm1zAR5z/h/litE7/8O2ietija3Q/qtl2TOXJdCA6sgjJX2WUql\n"
    b"ybrC55ct18NKf3qhpcEkGQvFU40rVYApJpi98DiZPYFdx1oBDp/f4uZ3ojpxRVFT\n"
    b"cDwcJLfNRCPUhormsY7fDS9xSyThiHsW9mjJYdcaKQkwYZ0F11yB\n"
    b"-----END CERTIFICATE-----\n"
)


@pytest.fixture
def mock_cryptography(monkeypatch):
    pass


class TestAgentIdentityUtils:
    def test__is_agent_identity_certificate_invalid(self, tmpdir):
        cert_path = tmpdir.join("non_agent_cert.pem")
        cert_path.write(NON_AGENT_IDENTITY_CERT_BYTES)
        assert not _agent_identity_utils._is_agent_identity_certificate(
            cert_path.read_binary()
        )

    # TODO(negarb): get a mock agent identity certificate and update these unit tests.
    # def test__is_agent_identity_certificate_valid(self, tmpdir):
    #     cert_path = tmpdir.join("agent_cert.pem")
    #     cert_path.write(AGENT_IDENTITY_CERT_BYTES)
    #     assert _agent_identity_utils._is_agent_identity_certificate(cert_path.read_binary())

    # def test_calculate_certificate_fingerprint(self, tmpdir):
    #     cert_path = tmpdir.join("agent_cert.pem")
    #     cert_path.write(AGENT_IDENTITY_CERT_BYTES)
    #     fingerprint = _agent_identity_utils.calculate_certificate_fingerprint(
    #         cert_path.read_binary()
    #     )
    #     # base64(sha256(DER-encoded-cert))
    #     assert fingerprint == ""

    @mock.patch("google.auth._agent_identity_utils._is_agent_identity_certificate")
    def test_should_request_bound_token(self, mock_is_agent, monkeypatch):
        # Agent cert, default env var (opt-in)
        mock_is_agent.return_value = True
        monkeypatch.delenv(
            "GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES", raising=False
        )
        assert _agent_identity_utils.should_request_bound_token(b"cert")

        # Agent cert, explicit opt-in
        monkeypatch.setenv(
            "GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES", "true"
        )
        assert _agent_identity_utils.should_request_bound_token(b"cert")

        # Agent cert, explicit opt-out
        monkeypatch.setenv(
            "GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES", "false"
        )
        assert not _agent_identity_utils.should_request_bound_token(b"cert")

        # Non-agent cert, opt-in
        mock_is_agent.return_value = False
        monkeypatch.setenv(
            "GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES", "true"
        )
        assert not _agent_identity_utils.should_request_bound_token(b"cert")

    def test_get_agent_identity_certificate_path_success(self, tmpdir, monkeypatch):
        cert_path = tmpdir.join("cert.pem")
        cert_path.write("cert_content")
        config_path = tmpdir.join("config.json")
        config_path.write(
            json.dumps({"cert_configs": {"workload": {"cert_path": str(cert_path)}}})
        )
        monkeypatch.setenv(
            environment_vars.GOOGLE_API_CERTIFICATE_CONFIG, str(config_path)
        )

        result = _agent_identity_utils.get_agent_identity_certificate_path()
        assert result == str(cert_path)

    @mock.patch("time.sleep")
    def test_get_agent_identity_certificate_path_retry(
        self, mock_sleep, tmpdir, monkeypatch
    ):
        config_path = tmpdir.join("config.json")
        monkeypatch.setenv(
            environment_vars.GOOGLE_API_CERTIFICATE_CONFIG, str(config_path)
        )

        # File doesn't exist initially
        with pytest.raises(exceptions.RefreshError):
            _agent_identity_utils.get_agent_identity_certificate_path()

        assert mock_sleep.call_count == 4

    def test_get_agent_identity_certificate_path_failure(self, tmpdir, monkeypatch):
        config_path = tmpdir.join("non_existent_config.json")
        monkeypatch.setenv(
            environment_vars.GOOGLE_API_CERTIFICATE_CONFIG, str(config_path)
        )

        with pytest.raises(exceptions.RefreshError) as excinfo:
            _agent_identity_utils.get_agent_identity_certificate_path()

        assert "not found after multiple retries" in str(excinfo.value)
