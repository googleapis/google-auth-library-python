# Copyright 2026 Google LLC
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
import os
import ssl
from unittest import mock

import pytest

from google.auth import exceptions
from google.auth.aio import credentials
from google.auth.aio.transport import sessions

# This is the valid "workload" format the library expects
VALID_WORKLOAD_CONFIG = {
    "version": 1,
    "cert_configs": {
        "workload": {"cert_path": "/tmp/mock_cert.pem", "key_path": "/tmp/mock_key.pem"}
    },
}


class TestSessionsMtls:
    @mock.patch.dict(os.environ, {"GOOGLE_API_USE_CLIENT_CERTIFICATE": "true"})
    @mock.patch("os.path.exists")
    @mock.patch(
        "builtins.open",
        new_callable=mock.mock_open,
        read_data=json.dumps(VALID_WORKLOAD_CONFIG),
    )
    @mock.patch("google.auth.aio.transport.mtls.get_client_cert_and_key")
    @mock.patch("ssl.create_default_context")
    @pytest.mark.asyncio
    async def test_configure_mtls_channel(
        self, mock_ssl, mock_helper, mock_file, mock_exists
    ):
        """
        Tests that the mTLS channel configures correctly when a
        valid workload config is mocked.
        """
        mock_exists.return_value = True
        mock_helper.return_value = (True, b"fake_cert_data", b"fake_key_data")

        mock_context = mock.Mock(spec=ssl.SSLContext)
        mock_ssl.return_value = mock_context

        mock_creds = mock.Mock(spec=credentials.Credentials)
        session = sessions.AsyncAuthorizedSession(mock_creds)
        await session.configure_mtls_channel()

        assert session._is_mtls is True
        assert mock_context.load_cert_chain.called

    @mock.patch.dict(os.environ, {"GOOGLE_API_USE_CLIENT_CERTIFICATE": "true"})
    @mock.patch("os.path.exists")
    @pytest.mark.asyncio
    async def test_configure_mtls_channel_disabled(self, mock_exists):
        """
        Tests behavior when the config file does not exist.
        """
        mock_exists.return_value = False
        mock_creds = mock.Mock(spec=credentials.Credentials)

        session = sessions.AsyncAuthorizedSession(mock_creds)
        await session.configure_mtls_channel()

        # If the file doesn't exist, it shouldn't error; it just won't use mTLS
        assert session._is_mtls is False

    @mock.patch("os.path.exists")
    @mock.patch(
        "builtins.open", new_callable=mock.mock_open, read_data='{"invalid": "format"}'
    )
    @pytest.mark.asyncio
    async def test_configure_mtls_channel_invalid_format(self, mock_file, mock_exists):
        """
        Verifies that the MutualTLSChannelError is raised for bad formats.
        """
        mock_exists.return_value = True
        mock_creds = mock.Mock(spec=credentials.Credentials)

        session = sessions.AsyncAuthorizedSession(mock_creds)
        with pytest.raises(exceptions.MutualTLSChannelError):
            await session.configure_mtls_channel()

    @mock.patch.dict(os.environ, {"GOOGLE_API_USE_CLIENT_CERTIFICATE": "true"})
    @pytest.mark.asyncio
    @mock.patch(
        "google.auth.aio.transport.mtls.has_default_client_cert_source",
        return_value=True,
    )
    async def test_configure_mtls_channel_mock_callback(self, mock_has_cert):
        """
        Tests mTLS configuration using bytes-returning callback.
        """

        def mock_callback():
            return (b"fake_cert_bytes", b"fake_key_bytes")

        mock_creds = mock.Mock(spec=credentials.Credentials)

        with mock.patch("ssl.SSLContext.load_cert_chain"):
            session = sessions.AsyncAuthorizedSession(mock_creds)
            await session.configure_mtls_channel(client_cert_callback=mock_callback)

            assert session._is_mtls is True
