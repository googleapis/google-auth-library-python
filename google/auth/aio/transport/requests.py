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

import aiohttp


class Response:

    """
    Instances of Response class are returned by 
    ``google.auth.aio.transport.requests.AuthorizedSession`` and provide methods to interact
    with the response data.
    
    
    Args:
        response (aiohttp.ClientResponse): An instance of aiohttp.ClientResponse.

    Attributes:
        status (int): The HTTP status code of the response.
        headers (dict): A dictionary of HTTP headers.
        content (coroutine): The raw content of the response.

    
    """
    
    def __init__(self, response: aiohttp.ClientResponse):
        self._response = response

    @property
    def status(self):
        return self._response.status
    
    @property
    def headers(self):
        return self._response.headers
    
    @property
    def content(self):
        return self._response.content
    
    async def text(self):
        return await self._response.text()
    
    async def json(self):
        return await self._response.json()
    
    async def read(self):
        return await self._response.read()
    
    async def close(self):
        return await self._response.close()
    

class Request:
    pass