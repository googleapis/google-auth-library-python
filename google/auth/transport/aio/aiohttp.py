# Lint as: python3
# Copyright 2016 Google Inc.
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
#
#
"""Aiohttp adapter transport adapter.

Uses aiohttp as an http client for refreshing credentials.
"""

from typing import Any, Mapping, Optional, Text

import aiohttp

from google.auth import exceptions
import google.auth.transport.aio as aio_transport


class Request(aio_transport.Request):
    """Aiohttp transport request adapter."""

    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        """Aiohttp request constructor.

        Aiohttp recommends using application-wide sessions, so a ClientSession can
        be optionally passed into the creation of these requests. If no session is
        provided, the basic API will be used instead.

        Args:
          session: ClientSession which will be used in requests if provided.
        """
        self._session = session

    async def __call__(
        self,
        url: Text,
        method: Text = "get",
        body: Any = None,
        headers: Mapping[Text, Text] = None,
        **kwargs
    ) -> aio_transport.Response:
        """Make an HTTP request.

        Same as google.auth.transport.Request, but without
        a timeout parameter as asyncio.wait_for should be used instead.

        Args:
          url: The URI to be requested.
          method: The HTTP method to use for the request. Defaults to 'GET'.
          body: The payload / body in HTTP request.
          headers: Request headers.
          **kwargs: Additionally arguments passed on to the transport's request
            method.

        Returns:
          Response: The HTTP response.

        Raises:
          google.auth.exceptions.TransportError: If any exception occurred.
        """
        request = self._session.request if self._session else aiohttp.request
        try:
            async with request(
                method, url, data=body, headers=headers, **kwargs
            ) as resp:
                status = resp.status
                headers = resp.headers
                content = await resp.read()
            return aio_transport.Response(status, headers, content)
        except aiohttp.ClientError as caught_exc:
            new_exc = exceptions.TransportError(caught_exc)
            raise new_exc from caught_exc
