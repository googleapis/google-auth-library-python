import os
import pytest
from unittest import mock
from google.auth import exceptions
# Assuming the provided code is in a file named google/auth/transport/aio/mtls_helper.py
from google.auth.transport.aio import mtls_helper

CERT_DATA = b"client-cert"
KEY_DATA = b"client-key"

class TestMTLSHelper:

    @mock.patch("os.path.expanduser")
    @mock.patch("os.path.exists")
    def test__check_config_path_exists(self, mock_exists, mock_expand):
        mock_expand.side_effect = lambda x: x.replace("~", "/home/user")
        mock_exists.return_value = True
        
        path = "/home/user/config.json"
        result = mtls_helper._check_config_path("~/config.json")
        
        assert result == path
        mock_exists.assert_called_with(path)

    @mock.patch("os.path.exists", return_value=False)
    def test__check_config_path_not_found(self, mock_exists):
        result = mtls_helper._check_config_path("nonexistent.json")
        assert result is None

    @mock.patch("google.auth.transport.aio.mtls_helper._check_config_path")
    @mock.patch("os.getenv")
    def test_has_default_client_cert_source_default_path(self, mock_getenv, mock_check):
        # Case 1: Default config path exists
        mock_check.side_effect = lambda x: x if x == mtls_helper.CERTIFICATE_CONFIGURATION_DEFAULT_PATH else None
        
        assert mtls_helper.has_default_client_cert_source() is True

    @mock.patch("google.auth.transport.aio.mtls_helper._check_config_path")
    @mock.patch("os.getenv")
    def test_has_default_client_cert_source_env_var(self, mock_getenv, mock_check):
        # Case 2: Default path doesn't exist, but env var path does
        custom_path = "/custom/path.json"
        mock_check.side_effect = lambda x: x if x == custom_path else None
        mock_getenv.return_value = custom_path
        
        assert mtls_helper.has_default_client_cert_source() is True

    @mock.patch("google.auth.transport.aio.mtls_helper._check_config_path", return_value=None)
    def test_has_default_client_cert_source_none(self, mock_check):
        assert mtls_helper.has_default_client_cert_source() is False

    @mock.patch("google.auth.transport._mtls_helper._get_workload_cert_and_key")
    def test_get_client_ssl_credentials_success(self, mock_workload):
        mock_workload.return_value = (CERT_DATA, KEY_DATA)
        
        success, cert, key, passphrase = mtls_helper.get_client_ssl_credentials()
        
        assert success is True
        assert cert == CERT_DATA
        assert key == KEY_DATA
        assert passphrase is None

    @mock.patch("google.auth.transport._mtls_helper._get_workload_cert_and_key", return_value=(None, None))
    def test_get_client_ssl_credentials_fail(self, mock_workload):
        success, cert, key, passphrase = mtls_helper.get_client_ssl_credentials()
        assert success is False
        assert cert is None

    def test_get_client_cert_and_key_callback(self):
        # Callback should take priority
        callback = mock.Mock(return_value=(CERT_DATA, KEY_DATA))
        
        success, cert, key = mtls_helper.get_client_cert_and_key(callback)
        
        assert success is True
        assert cert == CERT_DATA
        assert key == KEY_DATA
        callback.assert_called_once()

    @mock.patch("google.auth.transport.aio.mtls_helper.get_client_ssl_credentials")
    def test_get_client_cert_and_key_default(self, mock_get_ssl):
        mock_get_ssl.return_value = (True, CERT_DATA, KEY_DATA, None)
        
        success, cert, key = mtls_helper.get_client_cert_and_key(None)
        
        assert success is True
        assert cert == CERT_DATA
        assert key == KEY_DATA
