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

"""Transport adapter for Base Requests."""

import os

import abc
from google.auth import transport


_DEFAULT_TIMEOUT = 120  # in second


class _BaseAuthorizedSession(metaclass=abc.ABCMeta):
    """Base class for a Request Session with credentials. This class is intended to capture
    the common logic between synchronous and asynchronous request sessions and is not intended to
    be instantiated directly.

    Args:
        credentials (google.auth._credentials_base.BaseCredentials): The credentials to
            add to the request.
        refresh_status_codes (Sequence[int]): Which HTTP status codes indicate
            that credentials should be refreshed and the request should be
            retried.
        max_refresh_attempts (int): The maximum number of times to attempt to
            refresh the credentials and retry the request.
        refresh_timeout (Optional[int]): The timeout value in seconds for
            credential refresh HTTP requests.
        auth_request (google.auth.transport.requests.Request):
            (Optional) An instance of
            :class:`~google.auth.transport.requests.Request` used when
            refreshing credentials. If not passed,
            an instance of :class:`~google.auth.transport.requests.Request`
            is created.
        default_host (Optional[str]): A host like "pubsub.googleapis.com".
            This is used when a self-signed JWT is created from service
            account credentials.
    """

    def __init__(
        self,
        credentials,
        refresh_status_codes=transport.DEFAULT_REFRESH_STATUS_CODES,
        max_refresh_attempts=transport.DEFAULT_MAX_REFRESH_ATTEMPTS,
        refresh_timeout=None,
        auth_request=None,
        default_host=None,
    ):
        self.credentials = credentials
        self._refresh_status_codes = refresh_status_codes
        self._max_refresh_attempts = max_refresh_attempts
        self._refresh_timeout = refresh_timeout
        self._is_mtls = False
        self._default_host = default_host
        self._auth_request = auth_request

    @abc.abstractmethod
    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        max_allowed_time=None,
        timeout=_DEFAULT_TIMEOUT,
        **kwargs
    ):
        raise NotImplementedError("Request must be implemented")

    @abc.abstractmethod
    def close(self):
        raise NotImplementedError("Close must be implemented")
