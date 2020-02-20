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

import mock

from google.auth.transport import _mtls_helper

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

with open(os.path.join(DATA_DIR, "privatekey.pub"), "rb") as fh:
    PRIVATE_KEY_BYTES = fh.read()

with open(os.path.join(DATA_DIR, "public_cert.pem"), "rb") as fh:
    PUBLIC_CERT_BYTES = fh.read()

CLIENT_SSL_CREDENTIALS = PUBLIC_CERT_BYTES + PRIVATE_KEY_BYTES

CONTEXT_AWARE_METADATA = {"cert_provider_command": ["some command"]}

CONTEXT_AWARE_METADATA_NO_CERT_PROVIDER_COMMAND = {}


class TestReadMetadataFile(object):
    def test_success(self):
        metadata_path = os.path.join(DATA_DIR, "context_aware_metadata.json")
        metadata = _mtls_helper.read_metadata_file(metadata_path)

        assert "cert_provider_command" in metadata

    def test_file_not_exist(self):
        metadata_path = os.path.join(DATA_DIR, "not_exist.json")
        metadata = _mtls_helper.read_metadata_file(metadata_path)

        assert metadata is None

    def test_file_not_json(self):
        # read a file which is not json format.
        metadata_path = os.path.join(DATA_DIR, "privatekey.pem")
        metadata = _mtls_helper.read_metadata_file(metadata_path)

        assert metadata is None


class TestGetClientSslCredentials(object):
    def create_mock_process(self, output, error):
        # There are two steps to execute a script with subprocess.Popen.
        # (1) process = subprocess.Popen([comannds])
        # (2) stdout, stderr = process.communicate()
        # This function creates a mock process which can be returned by a mock
        # subprocess.Popen. The mock process returns the given output and error
        # when mock_process.communicate() is called.
        mock_process = mock.Mock()
        attrs = {"communicate.return_value": (output, error)}
        mock_process.configure_mock(**attrs)
        return mock_process

    @mock.patch("subprocess.Popen", autospec=True)
    def test_success(self, mock_popen):
        mock_popen.return_value = self.create_mock_process(CLIENT_SSL_CREDENTIALS, b"")
        success, cert, key, output, error = _mtls_helper.get_client_ssl_credentials(
            CONTEXT_AWARE_METADATA, "linux"
        )

        assert all(
            [
                a == b
                for a, b in zip(
                    (success, cert, key, output, error),
                    (
                        True,
                        PUBLIC_CERT_BYTES,
                        PRIVATE_KEY_BYTES,
                        CLIENT_SSL_CREDENTIALS,
                        b"",
                    ),
                )
            ]
        )

    def test_not_linux_platform(self):
        success, cert, key, stdout, stderr = _mtls_helper.get_client_ssl_credentials(
            CONTEXT_AWARE_METADATA, "win32"
        )

        assert all(
            [
                a == b
                for a, b in zip(
                    (success, cert, key, stdout, stderr),
                    (False, None, None, None, None),
                )
            ]
        )

    def test_missing_cert_provider_command(self):
        success, cert, key, stdout, stderr = _mtls_helper.get_client_ssl_credentials(
            CONTEXT_AWARE_METADATA_NO_CERT_PROVIDER_COMMAND, "linux"
        )

        assert all(
            [
                a == b
                for a, b in zip(
                    (success, cert, key, stdout, stderr),
                    (False, None, None, None, None),
                )
            ]
        )

    @mock.patch("subprocess.Popen", autospec=True)
    def test_missing_cert(self, mock_popen):
        mock_popen.return_value = self.create_mock_process(PRIVATE_KEY_BYTES, b"")
        success, cert, key, output, error = _mtls_helper.get_client_ssl_credentials(
            CONTEXT_AWARE_METADATA, "linux"
        )

        assert all(
            [
                a == b
                for a, b in zip(
                    (success, cert, key, output, error),
                    (False, None, None, PRIVATE_KEY_BYTES, b""),
                )
            ]
        )

    @mock.patch("subprocess.Popen", autospec=True)
    def test_missing_key(self, mock_popen):
        mock_popen.return_value = self.create_mock_process(PUBLIC_CERT_BYTES, b"")
        success, cert, key, output, error = _mtls_helper.get_client_ssl_credentials(
            CONTEXT_AWARE_METADATA, "linux"
        )

        assert all(
            [
                a == b
                for a, b in zip(
                    (success, cert, key, output, error),
                    (False, None, None, PUBLIC_CERT_BYTES, b""),
                )
            ]
        )

    @mock.patch("subprocess.Popen", autospec=True)
    def test_cert_provider_returns_error(self, mock_popen):
        mock_popen.return_value = self.create_mock_process(b"", b"some error")
        success, cert, key, output, error = _mtls_helper.get_client_ssl_credentials(
            CONTEXT_AWARE_METADATA, "linux"
        )

        assert all(
            [
                a == b
                for a, b in zip(
                    (success, cert, key, output, error),
                    (False, None, None, b"", b"some error"),
                )
            ]
        )

    @mock.patch("subprocess.Popen", autospec=True)
    def test_popen_raise_exception(self, mock_popen):
        mock_popen.side_effect = OSError()
        success, cert, key, output, error = _mtls_helper.get_client_ssl_credentials(
            CONTEXT_AWARE_METADATA, "linux"
        )

        assert all(
            [
                a == b
                for a, b in zip(
                    (success, cert, key, output, error), (False, None, None, None, None)
                )
            ]
        )
