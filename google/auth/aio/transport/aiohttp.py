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
