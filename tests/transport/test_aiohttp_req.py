# Copyright 2016 Google LLC
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

# import datetime
# import functools
# import sys
# import asyncio
import aiohttp
from aioresponses import aioresponses
import freezegun
import mock
import pytest
from six.moves import http_client

# from google.auth import exceptions
import google.auth.credentials
from google.auth.transport import aiohttp_req
import google.auth.transport._mtls_helper
from tests.transport import async_compliance


@pytest.fixture
def frozen_time():
    with freezegun.freeze_time("1970-01-01 00:00:00", tick=False) as frozen:
        yield frozen


class TestRequestResponse(async_compliance.RequestResponseTests):
    @pytest.mark.asyncio
    def make_request(self):
        return aiohttp_req.Request()


"""
    @pytest.mark.asyncio
    async def test_timeout(self):
        http = asynctest.mock.create_autospec(aiohttp.ClientSession, instance=True)
        #breakpoint()
        request = google.auth.transport.aiohttp_req.Request(http)
        await request(url="http://example.com", method="GET", timeout=5)
        assert http.request.call_args[1]["timeout"] == 5
"""


class CredentialsStub(google.auth.credentials.Credentials):
    def __init__(self, token="token"):
        super(CredentialsStub, self).__init__()
        self.token = token

    def apply(self, headers, token=None):
        headers["authorization"] = self.token

    def before_request(self, request, method, url, headers):
        self.apply(headers)

    def refresh(self, request):
        self.token += "1"


def make_response(status=http_client.OK, data=None):
    TEST_URL = "http://example.com/"
    method = "GET"
    response = aiohttp.ClientResponse(method, TEST_URL)
    response.status_code = status
    response._content = data
    return response


class TestAuthorizedSession(object):
    TEST_URL = "http://example.com/"
    method = "GET"

    def test_constructor(self):
        authed_session = google.auth.transport.aiohttp_req.AuthorizedSession(
            mock.sentinel.credentials
        )

        assert authed_session.credentials == mock.sentinel.credentials

    def test_constructor_with_auth_request(self):
        http = mock.create_autospec(aiohttp.ClientSession)
        auth_request = google.auth.transport.aiohttp_req.Request(http)

        # breakpoint()
        authed_session = google.auth.transport.aiohttp_req.AuthorizedSession(
            mock.sentinel.credentials, auth_request=auth_request
        )

        assert authed_session._auth_request == auth_request

    @pytest.mark.asyncio
    async def test_request(self):
        with aioresponses() as mocked:
            credentials, project_id = google.auth.default()
            mocked.get(self.TEST_URL, status=200, body="test")
            resp = await aiohttp_req.AuthorizedSession(credentials).request(
                "GET", "http://example.com/"
            )

            assert resp.status == 200
            assert "test" == await resp.text()

    @pytest.mark.asyncio
    async def test_ctx(self):
        with aioresponses() as mocked:
            credentials, project_id = google.auth.default()
            mocked.get("http://test.example.com", payload=dict(foo="bar"))
            resp = await aiohttp_req.AuthorizedSession(credentials).request(
                "GET", "http://test.example.com"
            )
            data = await resp.json()

            assert dict(foo="bar") == data

    @pytest.mark.asyncio
    async def test_http_headers(self):
        with aioresponses() as mocked:
            credentials, project_id = google.auth.default()
            mocked.post(
                "http://example.com",
                payload=dict(),
                headers=dict(connection="keep-alive"),
            )

            resp = await aiohttp_req.AuthorizedSession(credentials).request(
                "POST", "http://example.com"
            )

            assert resp.headers["Connection"] == "keep-alive"

    @pytest.mark.asyncio
    async def test_regexp_example(self):
        with aioresponses() as mocked:
            credentials, project_id = google.auth.default()
            mocked.get("http://example.com", status=500)
            mocked.get("http://example.com", status=200)

            resp1 = await aiohttp_req.AuthorizedSession(credentials).request(
                "GET", "http://example.com"
            )
            resp2 = await aiohttp_req.AuthorizedSession(credentials).request(
                "GET", "http://example.com"
            )

            assert resp1.status == 500
            assert resp2.status == 200
