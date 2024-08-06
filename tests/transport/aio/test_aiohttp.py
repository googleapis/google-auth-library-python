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

import google.auth.aio.transport.aiohttp as auth_aiohttp
import pytest  # type: ignore
import asyncio
from google.auth.exceptions import TimeoutError
from unittest.mock import patch


@pytest.fixture
async def simple_async_task():
    await asyncio.sleep(0.1)
    return True


@pytest.fixture
async def long_running_async_task():
    await asyncio.sleep(0.3)
    return True


class TestTimeoutGuard(object):
    def make_timeout_guard(self, timeout):
        return auth_aiohttp.timeout_guard(timeout)

    @pytest.mark.asyncio
    async def test_timeout_with_single_async_task_within_bounds(
        self, simple_async_task
    ):
        task = False
        async with self.make_timeout_guard(timeout=0.2) as with_timeout:
            task = await with_timeout(simple_async_task)

        # Task succeeds.
        assert task is True

    @pytest.mark.asyncio
    async def test_timeout_with_single_async_task_out_of_bounds(
        self, simple_async_task
    ):
        task = False
        with pytest.raises(TimeoutError) as exc:
            async with self.make_timeout_guard(timeout=0.1) as with_timeout:
                task = await with_timeout(simple_async_task)

        # Task does not succeed and the context manager times out i.e. no remaining time left.
        assert task is False
        assert exc.match("Context manager exceeded the configured timeout of 0.1s.")

    @pytest.mark.asyncio
    async def test_timeout_with_multiple_async_tasks_within_bounds(
        self, simple_async_task, long_running_async_task
    ):
        task_1 = task_2 = False
        async with self.make_timeout_guard(timeout=0.5) as with_timeout:

            task_1 = await with_timeout(simple_async_task)
            task_2 = await with_timeout(long_running_async_task)

        # Tasks succeed.
        assert task_1 is True
        assert task_2 is True

    @pytest.mark.asyncio
    async def test_timeout_with_multiple_async_tasks_out_of_bounds(
        self, simple_async_task, long_running_async_task
    ):
        task_1 = task_2 = False
        with pytest.raises(TimeoutError) as exc:
            async with self.make_timeout_guard(timeout=0.4) as with_timeout:

                # First task succeeds
                task_1 = await with_timeout(simple_async_task)
                task_2 = await with_timeout(long_running_async_task)

        # First task succeeds.
        assert task_1 is True
        # Second task fails and the context manager times out i.e. no remaining time left.
        assert task_2 is False

        assert exc.match("Context manager exceeded the configured timeout of 0.4s.")

    @pytest.mark.asyncio
    async def test_timeout_with_async_task_timing_out_before_context(
        self, simple_async_task
    ):
        task_1 = False
        with pytest.raises(TimeoutError) as exc:
            async with self.make_timeout_guard(timeout=0.4) as with_timeout:
                with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
                    task_1 = await with_timeout(simple_async_task)

        # Task does not complete i.e. the operation times out.
        assert task_1 is False
        assert exc.match(
            f"The operation {simple_async_task} exceeded the configured timeout of 0.4s."
        )
