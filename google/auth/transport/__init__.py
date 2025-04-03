# Copyright 2016 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Transport - HTTP client library support."""

import abc
import http.client as http_client
from typing import Mapping, Optional, Any


DEFAULT_RETRYABLE_STATUS_CODES = (
    http_client.INTERNAL_SERVER_ERROR,
    http_client.SERVICE_UNAVAILABLE,
    http_client.REQUEST_TIMEOUT,
    http_client.TOO_MANY_REQUESTS,
)

DEFAULT_REFRESH_STATUS_CODES = (http_client.UNAUTHORIZED,)

DEFAULT_MAX_REFRESH_ATTEMPTS = 2


class Response(metaclass=abc.ABCMeta):
    """HTTP Response data."""

    @property
    @abc.abstractmethod
    def status(self) -> int:
        """int: The HTTP status code."""
        ...

    @property
    @abc.abstractmethod
    def headers(self) -> Mapping[str, str]:
        """Mapping[str, str]: The HTTP response headers."""
        ...

    @property
    @abc.abstractmethod
    def data(self) -> bytes:
        """bytes: The response body."""
        ...


class Request(metaclass=abc.ABCMeta):
    """Interface for a callable that makes HTTP requests."""

    @abc.abstractmethod
    def __call__(
        self,
        url: str,
        method: str = "GET",
        body: Optional[bytes] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs: Any,
    ) -> Response:
        ...
