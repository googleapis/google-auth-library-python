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

import os
import re

import mock
from OpenSSL import crypto
import OpenSSL._util
from OpenSSL._util import lib
import pytest

from google.auth import environment_vars
from google.auth import exceptions
from google.auth.transport import _mtls_helper

CONTEXT_AWARE_METADATA = {"cert_provider_command": ["some command"]}

CONTEXT_AWARE_METADATA_NO_CERT_PROVIDER_COMMAND = {}

ENCRYPTED_EC_PRIVATE_KEY = b"""-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHkME8GCSqGSIb3DQEFDTBCMCkGCSqGSIb3DQEFDDAcBAgl2/yVgs1h3QICCAAw
DAYIKoZIhvcNAgkFADAVBgkrBgEEAZdVAQIECJk2GRrvxOaJBIGQXIBnMU4wmciT
uA6yD8q0FxuIzjG7E2S6tc5VRgSbhRB00eBO3jWmO2pBybeQW+zVioDcn50zp2ts
wYErWC+LCm1Zg3r+EGnT1E1GgNoODbVQ3AEHlKh1CGCYhEovxtn3G+Fjh7xOBrNB
saVVeDb4tHD4tMkiVVUBrUcTZPndP73CtgyGHYEphasYPzEz3+AU
-----END ENCRYPTED PRIVATE KEY-----"""

EC_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvCNi1NoDY1oMqPHIgXI8RBbTYGi/
brEjbre1nSiQW11xRTJbVeETdsuP0EAu2tG3PcRhhwDfeJ8zXREgTBurNw==
-----END PUBLIC KEY-----"""

PASSPHRASE = b"""-----BEGIN PASSPHRASE-----
password
-----END PASSPHRASE-----"""
PASSPHRASE_VALUE = b"password"

TPM_KEY_INFO = b"engine:engine_id:pkcs11:object=object1;token=token1"


def check_cert_and_key(content, expected_cert, expected_key):
    success = True

    cert_match = re.findall(_mtls_helper._CERT_REGEX, content)
    success = success and len(cert_match) == 1 and cert_match[0] == expected_cert

    key_match = re.findall(_mtls_helper._KEY_REGEX, content)
    success = success and len(key_match) == 1 and key_match[0] == expected_key

    return success


class TestCertAndKeyRegex(object):
    def test_cert_and_key(self):
        # Test single cert and single key
        check_cert_and_key(
            pytest.public_cert_bytes + pytest.private_key_bytes,
            pytest.public_cert_bytes,
            pytest.private_key_bytes,
        )
        check_cert_and_key(
            pytest.private_key_bytes + pytest.public_cert_bytes,
            pytest.public_cert_bytes,
            pytest.private_key_bytes,
        )

        # Test cert chain and single key
        check_cert_and_key(
            pytest.public_cert_bytes
            + pytest.public_cert_bytes
            + pytest.private_key_bytes,
            pytest.public_cert_bytes + pytest.public_cert_bytes,
            pytest.private_key_bytes,
        )
        check_cert_and_key(
            pytest.private_key_bytes
            + pytest.public_cert_bytes
            + pytest.public_cert_bytes,
            pytest.public_cert_bytes + pytest.public_cert_bytes,
            pytest.private_key_bytes,
        )

    def test_key(self):
        # Create some fake keys for regex check.
        KEY = b"""-----BEGIN PRIVATE KEY-----
        MIIBCgKCAQEA4ej0p7bQ7L/r4rVGUz9RN4VQWoej1Bg1mYWIDYslvKrk1gpj7wZg
        /fy3ZpsL7WqgsZS7Q+0VRK8gKfqkxg5OYQIDAQAB
        -----END PRIVATE KEY-----"""
        RSA_KEY = b"""-----BEGIN RSA PRIVATE KEY-----
        MIIBCgKCAQEA4ej0p7bQ7L/r4rVGUz9RN4VQWoej1Bg1mYWIDYslvKrk1gpj7wZg
        /fy3ZpsL7WqgsZS7Q+0VRK8gKfqkxg5OYQIDAQAB
        -----END RSA PRIVATE KEY-----"""
        EC_KEY = b"""-----BEGIN EC PRIVATE KEY-----
        MIIBCgKCAQEA4ej0p7bQ7L/r4rVGUz9RN4VQWoej1Bg1mYWIDYslvKrk1gpj7wZg
        /fy3ZpsL7WqgsZS7Q+0VRK8gKfqkxg5OYQIDAQAB
        -----END EC PRIVATE KEY-----"""

        check_cert_and_key(
            pytest.public_cert_bytes + KEY, pytest.public_cert_bytes, KEY
        )
        check_cert_and_key(
            pytest.public_cert_bytes + RSA_KEY, pytest.public_cert_bytes, RSA_KEY
        )
        check_cert_and_key(
            pytest.public_cert_bytes + EC_KEY, pytest.public_cert_bytes, EC_KEY
        )


class TestCheckaMetadataPath(object):
    def test_success(self):
        metadata_path = os.path.join(pytest.data_dir, "context_aware_metadata.json")
        returned_path = _mtls_helper._check_dca_metadata_path(metadata_path)
        assert returned_path is not None

    def test_failure(self):
        metadata_path = os.path.join(pytest.data_dir, "not_exists.json")
        returned_path = _mtls_helper._check_dca_metadata_path(metadata_path)
        assert returned_path is None


class TestReadMetadataFile(object):
    def test_success(self):
        metadata_path = os.path.join(pytest.data_dir, "context_aware_metadata.json")
        metadata = _mtls_helper._read_dca_metadata_file(metadata_path)

        assert "cert_provider_command" in metadata

    def test_file_not_json(self):
        # read a file which is not json format.
        metadata_path = os.path.join(pytest.data_dir, "privatekey.pem")
        with pytest.raises(exceptions.ClientCertError):
            _mtls_helper._read_dca_metadata_file(metadata_path)


class TestRunCertProviderCommand(object):
    def create_mock_process(self, output, error):
        # There are two steps to execute a script with subprocess.Popen.
        # (1) process = subprocess.Popen([comannds])
        # (2) stdout, stderr = process.communicate()
        # This function creates a mock process which can be returned by a mock
        # subprocess.Popen. The mock process returns the given output and error
        # when mock_process.communicate() is called.
        mock_process = mock.Mock()
        attrs = {"communicate.return_value": (output, error), "returncode": 0}
        mock_process.configure_mock(**attrs)
        return mock_process

    @mock.patch("subprocess.Popen", autospec=True)
    def test_success(self, mock_popen):
        mock_popen.return_value = self.create_mock_process(
            pytest.public_cert_bytes + pytest.private_key_bytes, b""
        )
        cert, key, passphrase = _mtls_helper._run_cert_provider_command(["command"])
        assert cert == pytest.public_cert_bytes
        assert key == pytest.private_key_bytes
        assert passphrase is None

        mock_popen.return_value = self.create_mock_process(
            pytest.public_cert_bytes + ENCRYPTED_EC_PRIVATE_KEY + PASSPHRASE, b""
        )
        cert, key, passphrase = _mtls_helper._run_cert_provider_command(
            ["command"], expect_encrypted_key=True
        )
        assert cert == pytest.public_cert_bytes
        assert key == ENCRYPTED_EC_PRIVATE_KEY
        assert passphrase == PASSPHRASE_VALUE

    @mock.patch("subprocess.Popen", autospec=True)
    def test_success_with_cert_chain(self, mock_popen):
        PUBLIC_CERT_CHAIN_BYTES = pytest.public_cert_bytes + pytest.public_cert_bytes
        mock_popen.return_value = self.create_mock_process(
            PUBLIC_CERT_CHAIN_BYTES + pytest.private_key_bytes, b""
        )
        cert, key, passphrase = _mtls_helper._run_cert_provider_command(["command"])
        assert cert == PUBLIC_CERT_CHAIN_BYTES
        assert key == pytest.private_key_bytes
        assert passphrase is None

        mock_popen.return_value = self.create_mock_process(
            PUBLIC_CERT_CHAIN_BYTES + ENCRYPTED_EC_PRIVATE_KEY + PASSPHRASE, b""
        )
        cert, key, passphrase = _mtls_helper._run_cert_provider_command(
            ["command"], expect_encrypted_key=True
        )
        assert cert == PUBLIC_CERT_CHAIN_BYTES
        assert key == ENCRYPTED_EC_PRIVATE_KEY
        assert passphrase == PASSPHRASE_VALUE

    @mock.patch("subprocess.Popen", autospec=True)
    def test_missing_cert(self, mock_popen):
        mock_popen.return_value = self.create_mock_process(
            pytest.private_key_bytes, b""
        )
        with pytest.raises(exceptions.ClientCertError):
            _mtls_helper._run_cert_provider_command(["command"])

        mock_popen.return_value = self.create_mock_process(
            ENCRYPTED_EC_PRIVATE_KEY + PASSPHRASE, b""
        )
        with pytest.raises(exceptions.ClientCertError):
            _mtls_helper._run_cert_provider_command(
                ["command"], expect_encrypted_key=True
            )

    @mock.patch("subprocess.Popen", autospec=True)
    def test_missing_key(self, mock_popen):
        mock_popen.return_value = self.create_mock_process(
            pytest.public_cert_bytes, b""
        )
        with pytest.raises(exceptions.ClientCertError):
            _mtls_helper._run_cert_provider_command(["command"])

        mock_popen.return_value = self.create_mock_process(
            pytest.public_cert_bytes + PASSPHRASE, b""
        )
        with pytest.raises(exceptions.ClientCertError):
            _mtls_helper._run_cert_provider_command(
                ["command"], expect_encrypted_key=True
            )

    @mock.patch("subprocess.Popen", autospec=True)
    def test_missing_passphrase(self, mock_popen):
        mock_popen.return_value = self.create_mock_process(
            pytest.public_cert_bytes + ENCRYPTED_EC_PRIVATE_KEY, b""
        )
        with pytest.raises(exceptions.ClientCertError):
            _mtls_helper._run_cert_provider_command(
                ["command"], expect_encrypted_key=True
            )

    @mock.patch("subprocess.Popen", autospec=True)
    def test_passphrase_not_expected(self, mock_popen):
        mock_popen.return_value = self.create_mock_process(
            pytest.public_cert_bytes + pytest.private_key_bytes + PASSPHRASE, b""
        )
        with pytest.raises(exceptions.ClientCertError):
            _mtls_helper._run_cert_provider_command(["command"])

    @mock.patch("subprocess.Popen", autospec=True)
    def test_encrypted_key_expected(self, mock_popen):
        mock_popen.return_value = self.create_mock_process(
            pytest.public_cert_bytes + pytest.private_key_bytes + PASSPHRASE, b""
        )
        with pytest.raises(exceptions.ClientCertError):
            _mtls_helper._run_cert_provider_command(
                ["command"], expect_encrypted_key=True
            )

    @mock.patch("subprocess.Popen", autospec=True)
    def test_unencrypted_key_expected(self, mock_popen):
        mock_popen.return_value = self.create_mock_process(
            pytest.public_cert_bytes + ENCRYPTED_EC_PRIVATE_KEY, b""
        )
        with pytest.raises(exceptions.ClientCertError):
            _mtls_helper._run_cert_provider_command(["command"])

    @mock.patch("subprocess.Popen", autospec=True)
    def test_cert_provider_returns_error(self, mock_popen):
        mock_popen.return_value = self.create_mock_process(b"", b"some error")
        mock_popen.return_value.returncode = 1
        with pytest.raises(exceptions.ClientCertError):
            _mtls_helper._run_cert_provider_command(["command"])

    @mock.patch("subprocess.Popen", autospec=True)
    def test_popen_raise_exception(self, mock_popen):
        mock_popen.side_effect = OSError()
        with pytest.raises(exceptions.ClientCertError):
            _mtls_helper._run_cert_provider_command(["command"])


class TestGetClientSslCredentials(object):
    @mock.patch(
        "google.auth.transport._mtls_helper._run_cert_provider_command", autospec=True
    )
    @mock.patch(
        "google.auth.transport._mtls_helper._read_dca_metadata_file", autospec=True
    )
    @mock.patch(
        "google.auth.transport._mtls_helper._check_dca_metadata_path", autospec=True
    )
    def test_success(
        self,
        mock_check_dca_metadata_path,
        mock_read_dca_metadata_file,
        mock_run_cert_provider_command,
    ):
        mock_check_dca_metadata_path.return_value = True
        mock_read_dca_metadata_file.return_value = {
            "cert_provider_command": ["command"]
        }
        mock_run_cert_provider_command.return_value = (b"cert", b"key", None)
        has_cert, cert, key, passphrase = _mtls_helper.get_client_ssl_credentials()
        assert has_cert
        assert cert == b"cert"
        assert key == b"key"
        assert passphrase is None

    @mock.patch(
        "google.auth.transport._mtls_helper._check_dca_metadata_path", autospec=True
    )
    def test_success_without_metadata(self, mock_check_dca_metadata_path):
        mock_check_dca_metadata_path.return_value = False
        has_cert, cert, key, passphrase = _mtls_helper.get_client_ssl_credentials()
        assert not has_cert
        assert cert is None
        assert key is None
        assert passphrase is None

    @mock.patch(
        "google.auth.transport._mtls_helper._run_cert_provider_command", autospec=True
    )
    @mock.patch(
        "google.auth.transport._mtls_helper._read_dca_metadata_file", autospec=True
    )
    @mock.patch(
        "google.auth.transport._mtls_helper._check_dca_metadata_path", autospec=True
    )
    def test_success_with_encrypted_key(
        self,
        mock_check_dca_metadata_path,
        mock_read_dca_metadata_file,
        mock_run_cert_provider_command,
    ):
        mock_check_dca_metadata_path.return_value = True
        mock_read_dca_metadata_file.return_value = {
            "cert_provider_command": ["command"]
        }
        mock_run_cert_provider_command.return_value = (b"cert", b"key", b"passphrase")
        has_cert, cert, key, passphrase = _mtls_helper.get_client_ssl_credentials(
            generate_encrypted_key=True
        )
        assert has_cert
        assert cert == b"cert"
        assert key == b"key"
        assert passphrase == b"passphrase"
        mock_run_cert_provider_command.assert_called_once_with(
            ["command", "--with_passphrase"], expect_encrypted_key=True
        )

    @mock.patch(
        "google.auth.transport._mtls_helper._read_dca_metadata_file", autospec=True
    )
    @mock.patch(
        "google.auth.transport._mtls_helper._check_dca_metadata_path", autospec=True
    )
    def test_missing_cert_command(
        self, mock_check_dca_metadata_path, mock_read_dca_metadata_file
    ):
        mock_check_dca_metadata_path.return_value = True
        mock_read_dca_metadata_file.return_value = {}
        with pytest.raises(exceptions.ClientCertError):
            _mtls_helper.get_client_ssl_credentials()

    @mock.patch(
        "google.auth.transport._mtls_helper._run_cert_provider_command", autospec=True
    )
    @mock.patch(
        "google.auth.transport._mtls_helper._read_dca_metadata_file", autospec=True
    )
    @mock.patch(
        "google.auth.transport._mtls_helper._check_dca_metadata_path", autospec=True
    )
    def test_customize_context_aware_metadata_path(
        self,
        mock_check_dca_metadata_path,
        mock_read_dca_metadata_file,
        mock_run_cert_provider_command,
    ):
        context_aware_metadata_path = "/path/to/metata/data"
        mock_check_dca_metadata_path.return_value = context_aware_metadata_path
        mock_read_dca_metadata_file.return_value = {
            "cert_provider_command": ["command"]
        }
        mock_run_cert_provider_command.return_value = (b"cert", b"key", None)

        has_cert, cert, key, passphrase = _mtls_helper.get_client_ssl_credentials(
            context_aware_metadata_path=context_aware_metadata_path
        )

        assert has_cert
        assert cert == b"cert"
        assert key == b"key"
        assert passphrase is None
        mock_check_dca_metadata_path.assert_called_with(context_aware_metadata_path)
        mock_read_dca_metadata_file.assert_called_with(context_aware_metadata_path)


class TestGetClientCertAndKey(object):
    def test_callback_success(self):
        callback = mock.Mock()
        callback.return_value = (pytest.public_cert_bytes, pytest.private_key_bytes)

        found_cert_key, cert, key = _mtls_helper.get_client_cert_and_key(callback)
        assert found_cert_key
        assert cert == pytest.public_cert_bytes
        assert key == pytest.private_key_bytes

    @mock.patch(
        "google.auth.transport._mtls_helper.get_client_ssl_credentials", autospec=True
    )
    def test_use_metadata(self, mock_get_client_ssl_credentials):
        mock_get_client_ssl_credentials.return_value = (
            True,
            pytest.public_cert_bytes,
            pytest.private_key_bytes,
            None,
        )

        found_cert_key, cert, key = _mtls_helper.get_client_cert_and_key()
        assert found_cert_key
        assert cert == pytest.public_cert_bytes
        assert key == pytest.private_key_bytes


class TestDecryptPrivateKey(object):
    def test_success(self):
        decrypted_key = _mtls_helper.decrypt_private_key(
            ENCRYPTED_EC_PRIVATE_KEY, PASSPHRASE_VALUE
        )
        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, decrypted_key)
        public_key = crypto.load_publickey(crypto.FILETYPE_PEM, EC_PUBLIC_KEY)
        x509 = crypto.X509()
        x509.set_pubkey(public_key)

        # Test the decrypted key works by signing and verification.
        signature = crypto.sign(private_key, b"data", "sha256")
        crypto.verify(x509, signature, b"data", "sha256")

    def test_crypto_error(self):
        with pytest.raises(crypto.Error):
            _mtls_helper.decrypt_private_key(
                ENCRYPTED_EC_PRIVATE_KEY, b"wrong_password"
            )


@mock.patch.dict(os.environ)
class TestLoadPkcs11PrivateKey(object):
    def test_invalid_key_info(self):
        with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
            _mtls_helper._load_pkcs11_private_key(b"key")

        assert excinfo.match("invalid key info format")

    def test_invalid_key_info_less_than_3_parts(self):
        with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
            _mtls_helper._load_pkcs11_private_key(b"engine:engine_id")

        assert excinfo.match("invalid key info format")

    def test_missing_so_path(self):
        with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
            _mtls_helper._load_pkcs11_private_key(TPM_KEY_INFO)

        assert excinfo.match(
            "GOOGLE_AUTH_PKCS11_SO_PATH is required for PKCS#11 support."
        )

    def test_missing_module_path(self):
        os.environ[environment_vars.PKCS11_SO_PATH] = "/path/to/libpkcs11.so"
        with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
            _mtls_helper._load_pkcs11_private_key(TPM_KEY_INFO)

        assert excinfo.match(
            "GOOGLE_AUTH_PKCS11_MODULE_PATH is required for PKCS#11 support."
        )

    @mock.patch.object(lib, "ENGINE_load_builtin_engines")
    @mock.patch.object(lib, "ENGINE_by_id", return_value=None)
    def test_failed_to_load_dynamic_engine(
        self, engine_by_id, engine_load_builtin_engines
    ):
        os.environ[environment_vars.PKCS11_SO_PATH] = "/path/to/libpkcs11.so"
        os.environ[environment_vars.PKCS11_MODULE_PATH] = "/path/to/tpm/module"

        with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
            _mtls_helper._load_pkcs11_private_key(TPM_KEY_INFO)

        assert excinfo.match("failed to load dynamic engine")

    # We will call ENGINE_ctrl_cmd_string 4 times where the 2nd parameter is
    # b"ID", b"SO_PATH", b"LOAD" and b"MODULE_PATH" respectively. This function
    # assigns the result for the calls in order.
    def cmd_side_effect(self, results):
        def side_effect(*args, **kwargs):
            if args[1] == b"ID":
                return results[0]
            elif args[1] == b"SO_PATH":
                return results[1]
            elif args[1] == b"LOAD":
                return results[2]
            else:  # args[1] == b"MODULE_PATH"
                return results[3]

        return side_effect

    @mock.patch.object(lib, "ENGINE_load_builtin_engines")
    @mock.patch.object(lib, "ENGINE_by_id", return_value=mock.Mock())
    @pytest.mark.parametrize(
        "cmd_results, error_message",
        [
            ([0, 1, 1, 1], "failed to set engine ID"),
            ([1, 0, 1, 1], "failed to set SO_PATH"),
            ([1, 1, 0, 1], "failed to set LOAD"),
            ([1, 1, 1, 0], "failed to set MODULE_PATH"),
        ],
    )
    def test_failed_to_call_engine_ctrl_cmd_string(
        self, engine_by_id, engine_load_builtin_engines, cmd_results, error_message
    ):
        os.environ[environment_vars.PKCS11_SO_PATH] = "/path/to/libpkcs11.so"
        os.environ[environment_vars.PKCS11_MODULE_PATH] = "/path/to/tpm/module"

        with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
            with mock.patch.object(
                lib,
                "ENGINE_ctrl_cmd_string",
                side_effect=self.cmd_side_effect(cmd_results),
            ):
                _mtls_helper._load_pkcs11_private_key(TPM_KEY_INFO)

        assert excinfo.match(error_message)

    @mock.patch.object(lib, "ENGINE_load_builtin_engines")
    @mock.patch.object(lib, "ENGINE_by_id", return_value=mock.Mock())
    @mock.patch.object(lib, "ENGINE_ctrl_cmd_string", side_effect=[1, 1, 1, 1])
    @mock.patch.object(lib, "ENGINE_init", return_value=0)
    def test_failed_to_init_engine(
        self, engine_init, engine_cmd, engine_by_id, engine_load_builtin_engines
    ):
        os.environ[environment_vars.PKCS11_SO_PATH] = "/path/to/libpkcs11.so"
        os.environ[environment_vars.PKCS11_MODULE_PATH] = "/path/to/tpm/module"

        with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
            _mtls_helper._load_pkcs11_private_key(TPM_KEY_INFO)

        assert excinfo.match("failed to init engine")

    @mock.patch.object(lib, "ENGINE_load_builtin_engines")
    @mock.patch.object(lib, "ENGINE_by_id", return_value=mock.Mock())
    @mock.patch.object(lib, "ENGINE_ctrl_cmd_string", side_effect=[1, 1, 1, 1])
    @mock.patch.object(lib, "ENGINE_init", return_value=1)
    def test_failed_to_load_private_key(
        self, engine_init, engine_cmd, engine_by_id, engine_load_builtin_engines
    ):
        os.environ[environment_vars.PKCS11_SO_PATH] = "/path/to/libpkcs11.so"
        os.environ[environment_vars.PKCS11_MODULE_PATH] = "/path/to/tpm/module"

        with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
            with mock.patch.object(lib, "ENGINE_load_private_key", return_value=None):
                _mtls_helper._load_pkcs11_private_key(TPM_KEY_INFO)

        assert excinfo.match("failed to load private key")

    @mock.patch.object(lib, "ENGINE_load_builtin_engines")
    @mock.patch.object(lib, "ENGINE_by_id", return_value=mock.Mock())
    @mock.patch.object(lib, "ENGINE_ctrl_cmd_string", side_effect=[1, 1, 1, 1])
    @mock.patch.object(lib, "ENGINE_init", return_value=1)
    def test_success(
        self, engine_init, engine_cmd, engine_by_id, engine_load_builtin_engines
    ):
        os.environ[environment_vars.PKCS11_SO_PATH] = "/path/to/libpkcs11.so"
        os.environ[environment_vars.PKCS11_MODULE_PATH] = "/path/to/tpm/module"

        loaded_key = mock.Mock()

        with mock.patch.object(lib, "ENGINE_load_private_key", return_value=loaded_key):
            assert _mtls_helper._load_pkcs11_private_key(TPM_KEY_INFO) == loaded_key


@mock.patch.object(crypto, "load_certificate")
@mock.patch.object(crypto, "load_privatekey")
class TestAddCertAndKeyToSslContext(object):
    def test_raw_key(self, crypto_load_privatekey, crypto_load_cert):
        ssl_context = mock.MagicMock()
        _mtls_helper._add_cert_and_key_to_ssl_context(
            ssl_context, b"fake_cert", b"fake_key"
        )

        # check crypto lib is used to load cert and key
        crypto_load_cert.assert_called()
        crypto_load_privatekey.assert_called()

        # check CA cert is used
        ssl_context.load_verify_locations.assert_called()

        # check cert and key are used in ssl context
        ssl_context._ctx.use_certificate.assert_called()
        ssl_context._ctx.use_privatekey.assert_called()

    @mock.patch.object(_mtls_helper, "_load_pkcs11_private_key")
    @mock.patch.object(lib, "SSL_CTX_use_PrivateKey")
    def test_tpm_key(
        self, ssl_ctx_use_key, load_pkcs11_key, crypto_load_privatekey, crypto_load_cert
    ):
        ssl_context = mock.MagicMock()
        _mtls_helper._add_cert_and_key_to_ssl_context(
            ssl_context, b"fake_cert", TPM_KEY_INFO
        )

        # check crypto lib is used to load cert
        crypto_load_cert.assert_called()

        # check key is loaded by _load_pkcs11_private_key instead of crypto api
        crypto_load_privatekey.assert_not_called()
        load_pkcs11_key.assert_called()

        # check CA cert is used
        ssl_context.load_verify_locations.assert_called()

        # check cert and key are used in ssl context
        ssl_context._ctx.use_certificate.assert_called()
        ssl_context._ctx.use_privatekey.assert_not_called()
        ssl_ctx_use_key.assert_called()

    @mock.patch.object(_mtls_helper, "_load_pkcs11_private_key")
    @mock.patch.object(lib, "SSL_CTX_use_PrivateKey", return_value=0)
    @mock.patch.object(
        OpenSSL._util,
        "exception_from_error_queue",
        return_value=exceptions.MutualTLSChannelError(""),
    )
    def test_tpm_key_exception(
        self,
        exception_from_queue,
        ssl_ctx_use_key,
        load_pkcs11_key,
        crypto_load_privatekey,
        crypto_load_cert,
    ):
        ssl_context = mock.MagicMock()
        with pytest.raises(exceptions.MutualTLSChannelError):
            _mtls_helper._add_cert_and_key_to_ssl_context(
                ssl_context, b"fake_cert", TPM_KEY_INFO
            )
