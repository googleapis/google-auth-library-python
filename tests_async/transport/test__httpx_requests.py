# Copyright 2023 Google LLC
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

import httpx
import pytest
from tests_async.transport import async_compliance

import google.auth._credentials_async
from google.auth.transport import _httpx_requests as httpx_requests


class TestCombinedResponse:
    @pytest.mark.asyncio
    async def test_status(self):
        response = httpx.Response(200)
        combined_response = httpx_requests._CombinedResponse(response)
        assert combined_response.status == 200

    @pytest.mark.asyncio
    async def test_headers(self):
        response = httpx.Response(200, headers={"header": "value"})
        combined_response = httpx_requests._CombinedResponse(response)
        assert combined_response.headers["header"] == "value"

    @pytest.mark.asyncio
    async def test_data(self):
        response = httpx.Response(200, content=b"data")
        combined_response = httpx_requests._CombinedResponse(response)
        # Check if data returns an async reader object
        assert await combined_response.data.read() == b"data"

    @pytest.mark.asyncio
    async def test_raw_content(self):
        response = httpx.Response(200, content=b"data")
        combined_response = httpx_requests._CombinedResponse(response)
        raw_content = await combined_response.raw_content()
        assert raw_content == b"data"

    @pytest.mark.asyncio
    async def test_content(self):
        response = httpx.Response(200, content=b"data")
        combined_response = httpx_requests._CombinedResponse(response)
        content = await combined_response.content()
        assert content == b"data"


class TestRequestResponse(async_compliance.RequestResponseTests):
    def make_request(self):
        return httpx_requests.Request()

    def make_with_parameter_request(self):
        client = httpx.AsyncClient()
        return httpx_requests.Request(client)

    @pytest.mark.asyncio
    async def test_unsupported_session(self):
        # httpx doesn't have the same auto_decompress limitation as the aiohttp wrapper
        pass

    @pytest.mark.asyncio
    async def test_timeout(self):
        client = mock.create_autospec(httpx.AsyncClient, instance=True)
        request = httpx_requests.Request(client)
        # We need to mock the client.request coroutine
        client.request.return_value = httpx.Response(200)
        await request(url="http://example.com", method="GET", timeout=5)
        client.request.assert_called_with(
            "GET", "http://example.com", content=None, headers=None, timeout=5
        )


class CredentialsStub(google.auth._credentials_async.Credentials):
    def __init__(self, token="token"):
        super(CredentialsStub, self).__init__()
        self.token = token

    def apply(self, headers, token=None):
        headers["authorization"] = self.token

    def refresh(self, request):
        self.token += "1"


class TestAuthorizedSession(object):
    TEST_URL = "http://example.com/"
    method = "GET"

    @pytest.mark.asyncio
    async def test_constructor(self):
        authed_session = httpx_requests.AuthorizedSession(mock.sentinel.credentials)
        assert authed_session.credentials == mock.sentinel.credentials

    @pytest.mark.asyncio
    async def test_constructor_with_auth_request(self):
        client = mock.create_autospec(httpx.AsyncClient, instance=True)
        auth_request = httpx_requests.Request(client)

        authed_session = httpx_requests.AuthorizedSession(
            mock.sentinel.credentials, auth_request=auth_request
        )

        assert authed_session._auth_request == auth_request

    @pytest.mark.asyncio
    async def test_request(self):
        credentials = mock.Mock(wraps=CredentialsStub())

        async def handler(request):
            return httpx.Response(200, content=b"test")

        transport = httpx.MockTransport(handler)

        async with httpx_requests.AuthorizedSession(credentials, transport=transport) as session:
            resp = await session.request(
                "GET",
                "http://example.com/",
                headers={"Keep-Alive": "timeout=5, max=1000", "fake": b"bytes"},
            )

            assert resp.status_code == 200
            assert resp.content == b"test"

    @pytest.mark.asyncio
    async def test_request_refresh(self):
        credentials = mock.Mock(wraps=CredentialsStub())

        attempts = 0
        async def handler(request):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(401)
            return httpx.Response(200, content=b"success")

        transport = httpx.MockTransport(handler)

        async with httpx_requests.AuthorizedSession(credentials, transport=transport) as session:
            response = await session.request("GET", "http://example.com")

            assert credentials.refresh.called
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_request_headers_bytes(self):
        credentials = mock.Mock(wraps=CredentialsStub())

        async def handler(request):
            assert request.headers["fake"] == "bytes"
            return httpx.Response(200, content=b"test")

        transport = httpx.MockTransport(handler)

        async with httpx_requests.AuthorizedSession(credentials, transport=transport) as session:
            await session.request(
                "GET",
                "http://example.com/",
                headers={"fake": b"bytes"},
            )

    @pytest.mark.asyncio
    async def test_url_validation(self):
        credentials = mock.Mock(wraps=CredentialsStub())
        async with httpx_requests.AuthorizedSession(credentials) as session:
             with pytest.raises(ValueError):
                await session.request("GET", "ftp://example.com")
