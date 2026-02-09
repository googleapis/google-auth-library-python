# Copyright 2024 Google LLC
# Licensed under the Apache License, Version 2.0...

from unittest import mock

import pytest

from google.auth import exceptions
from google.auth.aio.transport import mtls

CERT_DATA = b"client-cert"
KEY_DATA = b"client-key"


class TestMTLS:
    @mock.patch("google.auth.aio.transport.mtls.path.expanduser")
    @mock.patch("google.auth.aio.transport.mtls.path.exists")
    def test__check_config_path_exists(self, mock_exists, mock_expand):
        mock_expand.side_effect = lambda x: x.replace("~", "/home/user")
        mock_exists.return_value = True

        input_path = "~/config.json"
        expected_path = "/home/user/config.json"
        result = mtls._check_config_path(input_path)

        assert result == expected_path
        mock_exists.assert_called_with(expected_path)

    @mock.patch("google.auth.aio.transport.mtls.path.exists", return_value=False)
    def test__check_config_path_not_found(self, mock_exists):
        result = mtls._check_config_path("nonexistent.json")
        assert result is None

    @mock.patch("google.auth.aio.transport.mtls._check_config_path")
    @mock.patch("google.auth.aio.transport.mtls.getenv")
    def test_has_default_client_cert_source_env_var(self, mock_getenv, mock_check):
        # Mocking so the default path fails but the env var path succeeds
        custom_path = "/custom/path.json"
        mock_check.side_effect = lambda x: custom_path if x == custom_path else None
        mock_getenv.return_value = custom_path

        assert mtls.has_default_client_cert_source() is True

    @mock.patch("google.auth.transport._mtls_helper._get_workload_cert_and_key")
    def test_get_client_ssl_credentials_success(self, mock_workload):
        mock_workload.return_value = (CERT_DATA, KEY_DATA)

        success, cert, key, passphrase = mtls.get_client_ssl_credentials()

        assert success is True
        assert cert == CERT_DATA
        assert key == KEY_DATA
        assert passphrase is None

    def test_get_client_cert_and_key_callback(self):
        # The callback should be tried first and return immediately
        callback = mock.Mock(return_value=(CERT_DATA, KEY_DATA))

        success, cert, key = mtls.get_client_cert_and_key(callback)

        assert success is True
        assert cert == CERT_DATA
        assert key == KEY_DATA
        callback.assert_called_once()

    @mock.patch("google.auth.aio.transport.mtls.get_client_ssl_credentials")
    def test_get_client_cert_and_key_default(self, mock_get_ssl):
        # If no callback, it should call get_client_ssl_credentials
        mock_get_ssl.return_value = (True, CERT_DATA, KEY_DATA, None)

        success, cert, key = mtls.get_client_cert_and_key(None)

        assert success is True
        assert cert == CERT_DATA
        assert key == KEY_DATA
        mock_get_ssl.assert_called_with(generate_encrypted_key=False)

    @mock.patch("google.auth.transport._mtls_helper._get_workload_cert_and_key")
    def test_get_client_ssl_credentials_error(self, mock_workload):
        """Tests that ClientCertError is propagated correctly."""
        # Setup the mock to raise the specific google-auth exception
        mock_workload.side_effect = exceptions.ClientCertError(
            "Failed to read metadata"
        )

        # Verify that calling our function raises the same exception
        with pytest.raises(exceptions.ClientCertError, match="Failed to read metadata"):
            mtls.get_client_ssl_credentials()

    @mock.patch("google.auth.aio.transport.mtls.get_client_ssl_credentials")
    def test_get_client_cert_and_key_exception_propagation(self, mock_get_ssl):
        """Tests that get_client_cert_and_key propagates errors from its internal calls."""
        mock_get_ssl.side_effect = exceptions.ClientCertError(
            "Underlying credentials failed"
        )

        with pytest.raises(
            exceptions.ClientCertError, match="Underlying credentials failed"
        ):
            # Pass None for callback so it attempts to call get_client_ssl_credentials
            mtls.get_client_cert_and_key(client_cert_callback=None)
