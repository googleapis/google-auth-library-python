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

import base64
import hashlib
import json

import mock
from cryptography import x509
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


class TestAgentIdentityUtils:
    @mock.patch("cryptography.x509.load_pem_x509_certificate")
    def test_parse_certificate(self, mock_load_cert):
        result = _agent_identity_utils.parse_certificate(b"cert_bytes")
        mock_load_cert.assert_called_once_with(b"cert_bytes")
        assert result == mock_load_cert.return_value

    def test__is_agent_identity_certificate_invalid(self):
        cert = _agent_identity_utils.parse_certificate(NON_AGENT_IDENTITY_CERT_BYTES)
        assert not _agent_identity_utils._is_agent_identity_certificate(cert)

    def test__is_agent_identity_certificate_valid_spiffe(self):
        mock_cert = mock.MagicMock()
        mock_ext = mock.MagicMock()
        mock_san_value = mock.MagicMock()
        mock_cert.extensions.get_extension_for_oid.return_value = mock_ext
        mock_ext.value = mock_san_value
        mock_san_value.get_values_for_type.return_value = [
            "spiffe://agents.global.proj-12345.system.id.goog/workload"
        ]
        assert _agent_identity_utils._is_agent_identity_certificate(mock_cert)

    def test__is_agent_identity_certificate_non_matching_spiffe(self):
        mock_cert = mock.MagicMock()
        mock_ext = mock.MagicMock()
        mock_san_value = mock.MagicMock()
        mock_cert.extensions.get_extension_for_oid.return_value = mock_ext
        mock_ext.value = mock_san_value
        mock_san_value.get_values_for_type.return_value = [
            "spiffe://other.domain.com/workload"
        ]
        assert not _agent_identity_utils._is_agent_identity_certificate(mock_cert)

    def test__is_agent_identity_certificate_no_san(self):
        mock_cert = mock.MagicMock()
        mock_cert.extensions.get_extension_for_oid.side_effect = x509.ExtensionNotFound(
            "Test extension not found", None
        )
        assert not _agent_identity_utils._is_agent_identity_certificate(mock_cert)

    def test__is_agent_identity_certificate_not_spiffe_uri(self):
        mock_cert = mock.MagicMock()
        mock_ext = mock.MagicMock()
        mock_san_value = mock.MagicMock()
        mock_cert.extensions.get_extension_for_oid.return_value = mock_ext
        mock_ext.value = mock_san_value
        mock_san_value.get_values_for_type.return_value = ["https://example.com"]
        assert not _agent_identity_utils._is_agent_identity_certificate(mock_cert)

    def test_calculate_certificate_fingerprint(self):
        mock_cert = mock.MagicMock()
        mock_cert.public_bytes.return_value = b"der-bytes"

        expected_fingerprint = (
            base64.urlsafe_b64encode(hashlib.sha256(b"der-bytes").digest())
            .rstrip(b"=")
            .decode("utf-8")
        )

        fingerprint = _agent_identity_utils.calculate_certificate_fingerprint(mock_cert)

        assert fingerprint == expected_fingerprint

    @mock.patch("google.auth._agent_identity_utils._is_agent_identity_certificate")
    def test_should_request_bound_token(self, mock_is_agent, monkeypatch):
        # Agent cert, default env var (opt-in)
        mock_is_agent.return_value = True
        monkeypatch.delenv(
            environment_vars.GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES,
            raising=False,
        )
        assert _agent_identity_utils.should_request_bound_token(mock.sentinel.cert)

        # Agent cert, explicit opt-in
        monkeypatch.setenv(
            environment_vars.GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES,
            "true",
        )
        assert _agent_identity_utils.should_request_bound_token(mock.sentinel.cert)

        # Agent cert, explicit opt-out
        monkeypatch.setenv(
            environment_vars.GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES,
            "false",
        )
        assert not _agent_identity_utils.should_request_bound_token(mock.sentinel.cert)

        # Non-agent cert, opt-in
        mock_is_agent.return_value = False
        monkeypatch.setenv(
            environment_vars.GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES,
            "true",
        )
        assert not _agent_identity_utils.should_request_bound_token(mock.sentinel.cert)

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

        assert mock_sleep.call_count == 100

    @mock.patch("time.sleep")
    def test_get_agent_identity_certificate_path_failure(
        self, mock_sleep, tmpdir, monkeypatch
    ):
        config_path = tmpdir.join("non_existent_config.json")
        monkeypatch.setenv(
            environment_vars.GOOGLE_API_CERTIFICATE_CONFIG, str(config_path)
        )

        with pytest.raises(exceptions.RefreshError) as excinfo:
            _agent_identity_utils.get_agent_identity_certificate_path()

        assert "not found after multiple retries" in str(excinfo.value)
        assert mock_sleep.call_count == 100

    @mock.patch("time.sleep")
    @mock.patch("os.path.exists")
    def test_get_agent_identity_certificate_path_cert_not_found(
        self, mock_exists, mock_sleep, tmpdir, monkeypatch
    ):
        cert_path_str = str(tmpdir.join("cert.pem"))
        config_path = tmpdir.join("config.json")
        config_path.write(
            json.dumps({"cert_configs": {"workload": {"cert_path": cert_path_str}}})
        )
        monkeypatch.setenv(
            environment_vars.GOOGLE_API_CERTIFICATE_CONFIG, str(config_path)
        )

        def exists_side_effect(path):
            return path == str(config_path)

        mock_exists.side_effect = exists_side_effect

        with pytest.raises(exceptions.RefreshError):
            _agent_identity_utils.get_agent_identity_certificate_path()

        assert mock_sleep.call_count == 100
