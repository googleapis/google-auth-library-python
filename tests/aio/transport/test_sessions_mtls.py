# Copyright 2024 Google LLC
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

import unittest
from unittest import mock
import sys
import asyncio

# Create a mock for aiohttp
mock_aiohttp = mock.Mock()
# Ensure it looks like a package
mock_aiohttp.__name__ = "aiohttp"

# Mock aiohttp in sys.modules so imports work
with mock.patch.dict("sys.modules", {"aiohttp": mock_aiohttp}):
    from google.auth.aio.transport import sessions
    from google.auth.aio.transport import mtls
    import aiohttp

class TestSessionsMtls(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        # Reset mocks between tests
        mock_aiohttp.reset_mock()

    @mock.patch("google.auth.aio.transport.sessions._run_in_executor")
    async def test_configure_mtls_channel(
        self, _run_in_executor
    ):
        # Setup mocks
        mock_ssl_context = mock.Mock()
        
        # Side effect to return different values for different calls
        async def side_effect(func, *args):
            if func.__name__ == 'check_use_client_cert':
                return True
            if func.__name__ == 'get_client_cert_and_key':
                return (True, b"cert", b"key")
            if func.__name__ == 'make_client_cert_ssl_context':
                return mock_ssl_context
            return None
            
        _run_in_executor.side_effect = side_effect
        
        # Setup session
        creds = mock.Mock(spec=sessions.Credentials)
        # Mock AiohttpRequest to satisfy the isinstance check
        mock_auth_request = mock.Mock(spec=sessions.AiohttpRequest)
        # Mock close coroutine
        mock_auth_request.close = mock.AsyncMock()
        
        session = sessions.AsyncAuthorizedSession(creds, auth_request=mock_auth_request)
        
        # Call method (now async)
        await session.configure_mtls_channel()
        
        # Verify interactions
        self.assertEqual(_run_in_executor.call_count, 3)
        
        # Verify aiohttp interactions via the captured mock_aiohttp
        mock_aiohttp.TCPConnector.assert_called_once_with(ssl=mock_ssl_context)
        mock_aiohttp.ClientSession.assert_called_once()
        
        # Verify the session's auth_request was updated
        self.assertTrue(isinstance(session._auth_request, sessions.AiohttpRequest))
        # Verify it's a new instance (different from the mock we passed)
        self.assertIsNot(session._auth_request, mock_auth_request)
        # Verify old request was closed
        mock_auth_request.close.assert_awaited_once()
        
        # Verify is_mtls property
        self.assertTrue(session.is_mtls)

        # Verify the chain of objects
        mock_connector = mock_aiohttp.TCPConnector.return_value
        mock_client_session = mock_aiohttp.ClientSession.return_value
        
        # Ensure ClientSession was initialized with the correct connector
        mock_aiohttp.ClientSession.assert_called_with(connector=mock_connector)
        
        # Ensure the session's auth_request is holding the new client session
        self.assertEqual(session._auth_request._session, mock_client_session)

    @mock.patch("google.auth.aio.transport.sessions._run_in_executor")
    async def test_configure_mtls_channel_disabled(self, _run_in_executor):
        # Configure helper to return False for check_use_client_cert
        async def side_effect(func, *args):
            if func.__name__ == 'check_use_client_cert':
                return False
            return None
        _run_in_executor.side_effect = side_effect
        
        creds = mock.Mock(spec=sessions.Credentials)
        session = sessions.AsyncAuthorizedSession(creds)
        original_request = session._auth_request
        
        # Verify initial state
        self.assertFalse(session.is_mtls)
        
        await session.configure_mtls_channel()
        
        # Should not have changed
        self.assertIs(session._auth_request, original_request)
        # Verify is_mtls property remains False
        self.assertFalse(session.is_mtls)

if __name__ == '__main__':
    unittest.main()
