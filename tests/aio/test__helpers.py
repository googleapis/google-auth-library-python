# Copyright 2025 Google LLC
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
import logging
from unittest import mock

import pytest  # type: ignore
import pytest_asyncio  # type: ignore

from google.auth.aio import _helpers


@pytest.fixture
def logger():
    """Provides a basic logger instance for testing."""
    return logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_response_log_debug_enabled(logger, caplog):
    logger.setLevel(logging.DEBUG)
    with mock.patch("google.auth._helpers.CLIENT_LOGGING_SUPPORTED", True):
        await _helpers.response_log_async(logger, {"payload": None})
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.message == "Response received..."
    assert record.httpResponse == {"payload": None}


@pytest.mark.asyncio
async def test_response_log_debug_disabled(logger, caplog):
    logger.setLevel(logging.INFO)
    with mock.patch("google.auth._helpers.CLIENT_LOGGING_SUPPORTED", True):
        await _helpers.response_log_async(logger, "another_response")
    assert "Response received..." not in caplog.text


@pytest.mark.asyncio
async def test_response_log_debug_enabled_response_json(logger, caplog):
    class MockResponse:
        async def json(self):
            return {"key1": "value1", "key2": "value2", "key3": "value3"}

    response = MockResponse()
    logger.setLevel(logging.DEBUG)
    with mock.patch("google.auth._helpers.CLIENT_LOGGING_SUPPORTED", True):
        await _helpers.response_log_async(logger, response)
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.message == "Response received..."
    assert record.httpResponse == {"key1": "value1", "key2": "value2", "key3": "value3"}


@pytest.mark.asyncio
async def test_parse_response_async_json_valid():
    class MockResponse:
        async def json(self):
            return {"data": "test"}

    response = MockResponse()
    expected = {"data": "test"}
    assert await _helpers._parse_response_async(response) == expected


@pytest.mark.asyncio
async def test_parse_response_async_json_invalid():
    class MockResponse:
        def json(self):
            raise json.JSONDecodeError("msg", "doc", 0)

    response = MockResponse()
    assert await _helpers._parse_response_async(response) == response


@pytest.mark.asyncio
async def test_parse_response_async_no_json_method():
    response = "plain text"
    assert await _helpers._parse_response_async(response) == "plain text"


@pytest.mark.asyncio
async def test_parse_response_async_none():
    assert await _helpers._parse_response_async(None) is None
