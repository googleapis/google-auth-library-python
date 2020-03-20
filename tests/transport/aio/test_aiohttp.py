# Lint as: python3
# Copyright 2016 Google Inc.
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

"""Tests for google3.third_party.py.google.auth.transport.aio.aiohttp."""

import http
import json

import aiohttp
import pytest

from google.auth import exceptions
import google.auth.transport.aio.aiohttp as aiohttp_transport

pytest_plugins = "aiohttp.pytest_plugin"

TEST_RESPONSE = {"status": "OK"}


@pytest.fixture
def client(loop, aiohttp_client):
    app = aiohttp.web.Application()

    async def handle_request(request: aiohttp.web.Request):
        del request
        return aiohttp.web.Response(
            text=json.dumps(TEST_RESPONSE), content_type="application/json"
        )

    async def handle_request_poorly(request: aiohttp.web.Request):
        del request
        return

    app.router.add_get("/", handle_request)
    app.router.add_get("/broken", handle_request_poorly)
    return loop.run_until_complete(aiohttp_client(app))


# pylint: disable=redefined-outer-name
async def test_request(client):
    request = aiohttp_transport.Request(client)
    response = await request("/", body="body")
    response_body = response.data.decode("utf-8")
    response_json = json.loads(response_body)
    assert response.status == http.HTTPStatus.OK
    assert response_json == TEST_RESPONSE


# pylint: disable=redefined-outer-name
async def test_request_unsuccessful(client):
    request = aiohttp_transport.Request(client)
    with pytest.raises(exceptions.TransportError):
        await request("/broken", body="body")
