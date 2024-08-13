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

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest  # type: ignore

import google.auth.aio.transport.sessions as auth_sessions
from google.auth.exceptions import TimeoutError


@pytest.fixture
async def simple_async_task():
    return True


class TestTimeoutGuard(object):
    default_timeout = 1

    def make_timeout_guard(self, timeout):
        return auth_sessions.timeout_guard(timeout)

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
