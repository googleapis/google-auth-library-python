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

"""Transport adapter for Asynchronous HTTP Requests.
"""


from google.auth.exceptions import TimeoutError

import asyncio
import time
from contextlib import asynccontextmanager


@asynccontextmanager
async def timeout_guard(timeout):
    """
    timeout_guard is an asynchronous context manager to apply a timeout to an asynchronous block of code.

    Args:
        timeout (float): The time in seconds before the context manager times out.

    Raises:
        google.auth.exceptions.TimeoutError: If the code within the context exceeds the provided timeout.

    Usage:
        async with timeout_guard(10) as with_timeout:
            await with_timeout(async_function())
    """
    start = time.monotonic()
    total_timeout = timeout

    def _remaining_time():
        elapsed = time.monotonic() - start
        remaining = total_timeout - elapsed
        if remaining <= 0:
            raise TimeoutError(
                f"Context manager exceeded the configured timeout of {total_timeout}s."
            )
        return remaining

    async def with_timeout(coro):
        try:
            remaining = _remaining_time()
            response = await asyncio.wait_for(coro, remaining)
            return response
        except (asyncio.TimeoutError, TimeoutError) as e:
            raise TimeoutError(
                f"The operation {coro} exceeded the configured timeout of {total_timeout}s."
            ) from e

    try:
        yield with_timeout

    finally:
        _remaining_time()
