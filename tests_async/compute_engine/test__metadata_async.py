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

import datetime
import json
from unittest import mock
import os

import pytest
from google.auth import exceptions
from google.auth.compute_engine import _metadata_async
from google.auth import environment_vars


class _BytesAsyncReader:
    def __init__(self, data):
        self._data = data

    async def read(self, n=-1):
        return self._data


class MockResponse:
    def __init__(self, status=200, data=b"", headers=None):
        self.status = status
        self._data = data
        self.headers = headers or {}

    @property
    def data(self):
        return _BytesAsyncReader(self._data)


@pytest.fixture
def request_mock():
    return mock.AsyncMock()


@pytest.mark.asyncio
async def test_ping_success(request_mock):
    request_mock.return_value = MockResponse(
        status=200, headers={"metadata-flavor": "Google"}
    )
    assert await _metadata_async.ping(request_mock)


@pytest.mark.asyncio
async def test_ping_failure_status(request_mock):
    request_mock.return_value = MockResponse(
        status=500, headers={"metadata-flavor": "Google"}
    )
    assert not await _metadata_async.ping(request_mock)


@pytest.mark.asyncio
async def test_ping_failure_flavor(request_mock):
    request_mock.return_value = MockResponse(
        status=200, headers={"metadata-flavor": "NotGoogle"}
    )
    assert not await _metadata_async.ping(request_mock)


@pytest.mark.asyncio
async def test_ping_exception_retry(request_mock):
    # Fail twice, then succeed
    request_mock.side_effect = [
        exceptions.TransportError("error"),
        exceptions.TransportError("error"),
        MockResponse(status=200, headers={"metadata-flavor": "Google"}),
    ]
    assert await _metadata_async.ping(request_mock, retry_count=3)
    assert request_mock.call_count == 3


@pytest.mark.asyncio
async def test_ping_exception_fail(request_mock):
    request_mock.side_effect = exceptions.TransportError("error")
    assert not await _metadata_async.ping(request_mock, retry_count=3)
    assert request_mock.call_count == 3


@pytest.mark.asyncio
async def test_get_success(request_mock):
    request_mock.return_value = MockResponse(
        status=200, data=b"value", headers={"content-type": "text/plain"}
    )
    result = await _metadata_async.get(request_mock, "key")
    assert result == "value"


@pytest.mark.asyncio
async def test_get_json(request_mock):
    data = {"key": "value"}
    request_mock.return_value = MockResponse(
        status=200,
        data=json.dumps(data).encode("utf-8"),
        headers={"content-type": "application/json"},
    )
    result = await _metadata_async.get(request_mock, "key")
    assert result == data


@pytest.mark.asyncio
async def test_get_invalid_json(request_mock):
    request_mock.return_value = MockResponse(
        status=200,
        data=b"invalid json",
        headers={"content-type": "application/json"},
    )
    with pytest.raises(exceptions.TransportError):
        await _metadata_async.get(request_mock, "key")


@pytest.mark.asyncio
async def test_get_retry_status(request_mock):
    # 500 then 200
    request_mock.side_effect = [
        MockResponse(status=500),
        MockResponse(status=200, data=b"value", headers={"content-type": "text/plain"}),
    ]
    result = await _metadata_async.get(request_mock, "key", retry_count=3)
    assert result == "value"


@pytest.mark.asyncio
async def test_get_retry_exception(request_mock):
    # Exception then 200
    request_mock.side_effect = [
        exceptions.TransportError("error"),
        MockResponse(status=200, data=b"value", headers={"content-type": "text/plain"}),
    ]
    result = await _metadata_async.get(request_mock, "key", retry_count=3)
    assert result == "value"


@pytest.mark.asyncio
async def test_get_fail_status(request_mock):
    request_mock.return_value = MockResponse(status=404, data=b"Not Found")
    with pytest.raises(exceptions.TransportError):
        await _metadata_async.get(request_mock, "key")


@pytest.mark.asyncio
async def test_get_project_id(request_mock):
    request_mock.return_value = MockResponse(
        status=200,
        data=b"project_id",
        headers={"content-type": "text/plain"},
    )
    result = await _metadata_async.get_project_id(request_mock)
    assert result == "project_id"
    # Verify path
    args, _ = request_mock.call_args
    assert "project/project-id" in args[0] if "url=" not in str(request_mock.call_args) else request_mock.call_args.kwargs['url']
    # The URL construction logic handles the path joining


@pytest.mark.asyncio
async def test_get_service_account_info(request_mock):
    data = {"email": "me@example.com"}
    request_mock.return_value = MockResponse(
        status=200,
        data=json.dumps(data).encode("utf-8"),
        headers={"content-type": "application/json"},
    )
    result = await _metadata_async.get_service_account_info(request_mock)
    assert result == data


@pytest.mark.asyncio
async def test_get_service_account_token(request_mock):
    data = {"access_token": "token", "expires_in": 3600}
    request_mock.return_value = MockResponse(
        status=200,
        data=json.dumps(data).encode("utf-8"),
        headers={"content-type": "application/json"},
    )

    token, expiry = await _metadata_async.get_service_account_token(request_mock)
    assert token == "token"
    assert expiry > datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
