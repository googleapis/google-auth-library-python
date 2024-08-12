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

from unittest.mock import AsyncMock, Mock, patch

import pytest  # type: ignore

import asyncio

import google.auth.aio.transport.aiohttp as auth_aiohttp

from google.auth.exceptions import TimeoutError


@pytest.fixture
async def simple_async_task():
    return True


@pytest.fixture
def mock_response():
    response = Mock()
    response.status = 200
    response.headers = {"Content-Type": "application/json", "Content-Length": "100"}
    mock_iterator = AsyncMock()
    mock_iterator.__aiter__.return_value = iter(
        [b"Cavefish ", b"have ", b"no ", b"sight."]
    )
    response.content.iter_chunked = lambda chunk_size: mock_iterator
    response.read = AsyncMock(return_value=b"Cavefish have no sight.")
    response.close = AsyncMock()

    return auth_aiohttp.Response(response)


class TestResponse(object):
    @pytest.mark.asyncio
    async def test_response_status_code(self, mock_response):
        assert mock_response.status_code == 200

    @pytest.mark.asyncio
    async def test_response_headers(self, mock_response):
        assert mock_response.headers["Content-Type"] == "application/json"
        assert mock_response.headers["Content-Length"] == "100"

    @pytest.mark.asyncio
    async def test_response_content(self, mock_response):
        content = b"".join([chunk async for chunk in mock_response.content()])
        assert content == b"Cavefish have no sight."

    @pytest.mark.asyncio
    async def test_response_read(self, mock_response):
        content = await mock_response.read()
        assert content == b"Cavefish have no sight."

    @pytest.mark.asyncio
    async def test_response_close(self, mock_response):
        await mock_response.close()
        mock_response._response.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_response_content_stream(self, mock_response):
        itr = mock_response.content().__aiter__()
        content = []
        try:
            while True:
                chunk = await itr.__anext__()
                content.append(chunk)
        except StopAsyncIteration:
            pass
        assert b"".join(content) == b"Cavefish have no sight."


class TestTimeoutGuard(object):
    default_timeout = 1

    def make_timeout_guard(self, timeout):
        return auth_aiohttp.timeout_guard(timeout)

    @pytest.mark.asyncio
    async def test_timeout_with_simple_async_task_within_bounds(
        self, simple_async_task
    ):
        task = False
        with patch("time.monotonic", side_effect=[0, 0.25, 0.75]):
            with patch("asyncio.wait_for", lambda coro, timeout: coro):
                async with self.make_timeout_guard(
                    timeout=self.default_timeout
                ) as with_timeout:
                    task = await with_timeout(simple_async_task)

        # Task succeeds.
        assert task is True

    @pytest.mark.asyncio
    async def test_timeout_with_simple_async_task_out_of_bounds(
        self, simple_async_task
    ):
        task = False
        with patch("time.monotonic", side_effect=[0, 1, 1]):
            with patch("asyncio.wait_for", lambda coro, timeout: coro):
                with pytest.raises(TimeoutError) as exc:
                    async with self.make_timeout_guard(
                        timeout=self.default_timeout
                    ) as with_timeout:
                        task = await with_timeout(simple_async_task)

        # Task does not succeed and the context manager times out i.e. no remaining time left.
        assert task is False
        assert exc.match(
            f"Context manager exceeded the configured timeout of {self.default_timeout}s."
        )

    @pytest.mark.asyncio
    async def test_timeout_with_async_task_timing_out_before_context(
        self, simple_async_task
    ):
        task = False
        with pytest.raises(TimeoutError) as exc:
            async with self.make_timeout_guard(
                timeout=self.default_timeout
            ) as with_timeout:
                with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
                    task = await with_timeout(simple_async_task)

        # Task does not complete i.e. the operation times out.
        assert task is False
        assert exc.match(
            f"The operation {simple_async_task} exceeded the configured timeout of {self.default_timeout}s."
        )
