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

"""Async HTTP client library support.

Interfaces for asynchronous HTTP libraries. This provides a request adapter for
libraries built on top of asyncio, where HTTP requests are written as
coroutines.
"""

import abc
from typing import Any, Mapping, Text

from google.auth import transport


class Response(metaclass=abc.ABCMeta):
    """HTTP Response data."""

    def __init__(
        self,
        status: int = None,
        headers: Mapping[Text, Text] = None,
        data: bytes = None,
    ):
        self.status = status
        self.headers = headers
        self.data = data


class Request(metaclass=abc.ABCMeta):
    """Interface for a callable that makes HTTP requests.

    Specific transport implementations should provide an implementation of
    this that adapts their specific request / response API.
    """

    @abc.abstractmethod
    async def __call__(
        self,
        url: Text,
        method: Text = "get",
        body: Any = None,
        headers: Mapping[Text, Text] = None,
        **kwargs
    ) -> transport.Response:
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
