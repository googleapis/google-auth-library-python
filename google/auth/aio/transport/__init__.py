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


import http.client as http_client

DEFAULT_RETRYABLE_STATUS_CODES = (
    http_client.INTERNAL_SERVER_ERROR,
    http_client.SERVICE_UNAVAILABLE,
    http_client.REQUEST_TIMEOUT,
    http_client.TOO_MANY_REQUESTS,
)
"""Sequence[int]:  HTTP status codes indicating a request can be retried.
"""


DEFAULT_REFRESH_STATUS_CODES = (http_client.UNAUTHORIZED,)
"""Sequence[int]:  Which HTTP status code indicate that credentials should be
refreshed.
"""

DEFAULT_MAX_REFRESH_ATTEMPTS = 2
"""int: How many times to refresh the credentials and retry a request."""
