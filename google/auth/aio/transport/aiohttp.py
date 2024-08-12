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

"""Transport adapter for AIOHTTP Requests.
"""

try:
    import aiohttp
except ImportError as caught_exc:  # pragma: NO COVER
    raise ImportError(
        "The aiohttp library is not installed from please install the aiohttp package to use the aiohttp transport."
    ) from caught_exc
from typing import AsyncGenerator, Dict

from google.auth import _helpers
from google.auth.aio import transport
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


class Response(transport.Response):

    """
    Represents an HTTP response and its data. It is returned by ``google.auth.aio.transport.sessions.AuthorizedSession``.

    Args:
        response (aiohttp.ClientResponse): An instance of aiohttp.ClientResponse.

    Attributes:
        status_code (int): The HTTP status code of the response.
        headers (Dict[str, str]): A case-insensitive multidict proxy wiht HTTP headers of response.
    """

    def __init__(self, response: aiohttp.ClientResponse):
        self._response = response

    @property
    @_helpers.copy_docstring(transport.Response)
    def status_code(self) -> int:
        return self._response.status

    @property
    @_helpers.copy_docstring(transport.Response)
    def headers(self) -> Dict[str, str]:
        return {key: value for key, value in self._response.headers.items()}

    @_helpers.copy_docstring(transport.Response)
    async def content(self, chunk_size: int = 1024) -> AsyncGenerator[bytes, None]:
        async for chunk in self._response.content.iter_chunked(chunk_size):
            yield chunk

    @_helpers.copy_docstring(transport.Response)
    async def read(self) -> bytes:
        return await self._response.read()

    @_helpers.copy_docstring(transport.Response)
    async def close(self):
        return await self._response.close()
