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

"""Transport - Async HTTP client library support.

:mod:`google.auth.aio` is designed to work with various asynchronous client libraries such
as aiohttp. In order to work across these libraries with different
interfaces some abstraction is needed.

This module provides two interfaces that are implemented by transport adapters
to support HTTP libraries. :class:`Request` defines the interface expected by
:mod:`google.auth` to make asynchronous requests. :class:`Response` defines the interface
for the return value of :class:`Request`.
"""

import abc
from typing import AsyncGenerator, Dict


class Response(metaclass=abc.ABCMeta):
    """Asynchronous HTTP Response Interface."""

    @property
    @abc.abstractmethod
    def status_code(self) -> int:
        """
        The HTTP response status code..

        Returns:
            int: The HTTP response status code.

        """
        raise NotImplementedError("status_code must be implemented.")

    @property
    @abc.abstractmethod
    def headers(self) -> Dict[str, str]:
        """The HTTP response headers.

        Returns:
            Dict[str, str]: The HTTP response headers.
        """
        raise NotImplementedError("headers must be implemented.")

    @abc.abstractmethod
    async def content(self, chunk_size: int = 1024) -> AsyncGenerator[bytes, None]:
        """The raw response content.
        
        Args:
            chunk_size (int): The size of each chunk. Defaults to 1024.

        Yields:
            AsyncGenerator[bytes, None]: An asynchronous generator yielding
            response chunks as bytes.
        """
        raise NotImplementedError("content must be implemented.")

    @abc.abstractmethod
    async def close(self):
        """Close the response."""
        raise NotImplementedError("close must be implemented.")
