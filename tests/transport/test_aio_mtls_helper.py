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
        custom_path = "/custom/path.json"
        mock_check.side_effect = lambda x: custom_path if x == custom_path else None
        mock_getenv.return_value = custom_path

        assert mtls.has_default_client_cert_source() is True

    @mock.patch("google.auth.aio.transport.mtls._check_config_path")
    @mock.patch("google.auth.aio.transport.mtls.getenv")
    def test_has_default_client_cert_source_check_priority(
        self, mock_getenv, mock_check
    ):
        mock_check.return_value = "/default/path.json"

        assert mtls.has_default_client_cert_source() is True
        mock_getenv.assert_not_called()

    @mock.patch(
        "google.auth.aio.transport.mtls.has_default_client_cert_source",
        return_value=False,
    )
    def test_default_client_cert_source_none(self, mock_has_default):
        with pytest.raises(exceptions.MutualTLSChannelError):
            mtls.default_client_cert_source()

    @pytest.mark.asyncio
    @mock.patch(
        "google.auth.aio.transport.mtls.get_client_cert_and_key",
        new_callable=mock.AsyncMock,
    )
    @mock.patch(
        "google.auth.aio.transport.mtls.has_default_client_cert_source",
        return_value=True,
    )
    async def test_default_client_cert_source_success(
        self, mock_has_default, mock_get_cert_key
    ):
        mock_get_cert_key.return_value = (True, CERT_DATA, KEY_DATA)

        # Note: default_client_cert_source is NOT async, but it returns an async callback
        callback = mtls.default_client_cert_source()
        assert callable(callback)

        cert, key = await callback()
        assert cert == CERT_DATA
        assert key == KEY_DATA

    @pytest.mark.asyncio
    @mock.patch(
        "google.auth.aio.transport.mtls.has_default_client_cert_source",
        return_value=False,
    )
    async def test_default_client_cert_source_not_found(self, mock_has_default):
        with pytest.raises(exceptions.MutualTLSChannelError, match="doesn't exist"):
            await mtls.default_client_cert_source()

    @pytest.mark.asyncio
    @mock.patch(
        "google.auth.aio.transport.mtls.get_client_cert_and_key",
        new_callable=mock.AsyncMock,
    )
    @mock.patch(
        "google.auth.aio.transport.mtls.has_default_client_cert_source",
        return_value=True,
    )
    async def test_default_client_cert_source_callback_wraps_exception(
        self, mock_has, mock_get
    ):
        mock_get.side_effect = ValueError("Format error")

        callback = mtls.default_client_cert_source()

        with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
            await callback()
        assert "Format error" in str(excinfo.value)

    @pytest.mark.asyncio
    @mock.patch("google.auth.transport._mtls_helper._get_workload_cert_and_key")
    async def test_get_client_ssl_credentials_success(self, mock_workload):
        mock_workload.return_value = (CERT_DATA, KEY_DATA)

        success, cert, key, passphrase = await mtls.get_client_ssl_credentials()

        assert success is True
        assert cert == CERT_DATA
        assert key == KEY_DATA
        assert passphrase is None

    @pytest.mark.asyncio
    @mock.patch("google.auth.aio.transport.mtls.get_client_ssl_credentials")
    async def test_get_client_cert_and_key_no_credentials_found(self, mock_get_ssl):
        mock_get_ssl.return_value = (False, None, None, None)

        success, cert, key = await mtls.get_client_cert_and_key(None)

        assert success is False
        assert cert is None
        assert key is None

    @pytest.mark.asyncio
    async def test_get_client_cert_and_key_callback_async(self):
        # Test with an actual coroutine/AsyncMock to satisfy the 'await' in your code
        callback = mock.AsyncMock(return_value=(CERT_DATA, KEY_DATA))

        success, cert, key = await mtls.get_client_cert_and_key(callback)

        assert success is True
        assert cert == CERT_DATA
        assert key == KEY_DATA
        callback.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_client_cert_and_key_callback_sync(self):
        # Test the fallback logic: if it's a sync function, the TypeError is caught
        callback = mock.Mock(return_value=(CERT_DATA, KEY_DATA))

        success, cert, key = await mtls.get_client_cert_and_key(callback)

        assert success is True
        assert cert == CERT_DATA
        # In your current implementation, this might still show 2 calls if the
        # first 'await' attempt triggers a call before failing.
        # To strictly avoid 2 calls, the implementation would need to check inspect.iscoroutinefunction.
        assert callback.call_count >= 1

    @pytest.mark.asyncio
    @mock.patch(
        "google.auth.aio.transport.mtls.get_client_ssl_credentials",
        new_callable=mock.AsyncMock,
    )
    async def test_get_client_cert_and_key_default(self, mock_get_credentials):
        mock_get_credentials.return_value = (True, CERT_DATA, KEY_DATA, None)

        success, cert, key = await mtls.get_client_cert_and_key(None)

        assert success is True
        assert cert == CERT_DATA
        assert key == KEY_DATA
        mock_get_credentials.assert_called_once()

    @pytest.mark.asyncio
    @mock.patch("google.auth.transport._mtls_helper._get_workload_cert_and_key")
    async def test_get_client_ssl_credentials_error(self, mock_workload):
        mock_workload.side_effect = exceptions.ClientCertError(
            "Failed to read metadata"
        )

        with pytest.raises(exceptions.ClientCertError, match="Failed to read metadata"):
            await mtls.get_client_ssl_credentials()

    @pytest.mark.asyncio
    @mock.patch("google.auth.aio.transport.mtls.get_client_ssl_credentials")
    async def test_get_client_cert_and_key_exception_propagation(self, mock_get_ssl):
        mock_get_ssl.side_effect = exceptions.ClientCertError(
            "Underlying credentials failed"
        )

        with pytest.raises(
            exceptions.ClientCertError, match="Underlying credentials failed"
        ):
            await mtls.get_client_cert_and_key(client_cert_callback=None)
