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
from google.auth.aio import transport
from google.auth import _helpers


class Response(transport.Response):

    """
    Instances of Response class are returned by 
    ``google.auth.aio.transport.requests.AuthorizedSession`` and provide methods to interact
    with the response data.
    
    Args:
        response (aiohttp.ClientResponse): An instance of aiohttp.ClientResponse.

    Attributes:
        status_code (int): The HTTP status code of the response.
        headers (dict): A case-insensitive multidict proxy wiht HTTP headers of response.
        content (aiohttp.StreamReader): The payload stream which contains the response's body.
    """

    def __init__(self, response: aiohttp.ClientResponse):
        self._response = response

    @property
    @_helpers.copy_docstring(transport.Response)
    def status_code(self):
        return self._response.status

    @property
    @_helpers.copy_docstring(transport.Response)
    def headers(self):
        return self._response.headers

    @property
    @_helpers.copy_docstring(transport.Response)
    async def content(self):
        return self._response.content

    @_helpers.copy_docstring(transport.Response)
    async def close(self):
        return await self._response.close()
