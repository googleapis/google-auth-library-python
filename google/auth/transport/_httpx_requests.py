# Copyright 2020 Google LLC
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

"""Transport adapter for Async HTTP (httpx).

NOTE: This async support is experimental and marked internal. This surface may
change in minor releases.
"""

from __future__ import absolute_import

import asyncio
import functools
import inspect
import logging
import time

import httpx  # type: ignore

from google.auth import exceptions
from google.auth import transport
from google.auth import _helpers
from google.auth.aio import _helpers as _helpers_async
import google.auth.credentials

_LOGGER = logging.getLogger(__name__)

# Timeout can be re-defined depending on async requirement. Currently made 60s
# more than sync timeout.
_DEFAULT_TIMEOUT = 180  # in seconds


class _TimeoutGuard(object):
    """Simple context manager to track remaining timeout."""

    def __init__(self, timeout):
        self.remaining_timeout = timeout
        self._start = None

    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._start and self.remaining_timeout is not None:
            elapsed = time.monotonic() - self._start
            self.remaining_timeout -= elapsed
            if self.remaining_timeout < 0:
                self.remaining_timeout = 0

        # We don't suppress exceptions here; this is just for tracking time.
        # The actual timeout enforcement is done by the async transport (httpx).


class _BytesAsyncReader:
    """Simple async reader wrapper for bytes."""

    def __init__(self, data: bytes):
        self._data = data
        self._position = 0

    async def read(self, n: int = -1) -> bytes:
        if n == -1:
            res = self._data[self._position :]
            self._position = len(self._data)
            return res
        res = self._data[self._position : self._position + n]
        self._position += n
        return res


class _CombinedResponse(transport.Response):
    """
    In order to more closely resemble the `requests` interface, where a raw
    and deflated content could be accessed at once, this class lazily reads the
    stream in `transport.Response` so both return forms can be used.

    Unfortunately, httpx does not support a `raw` response, so this class
    presents all content as deflated. Alternatively, the `raw_content` method
    could raise a NotImplementedError.
    """

    def __init__(self, response: httpx.Response):
        self._httpx_response = response
        self._content = None

    @property
    def status(self):
        return self._httpx_response.status_code

    @property
    def headers(self):
        return self._httpx_response.headers

    @property
    def data(self):
        return _BytesAsyncReader(self._httpx_response.content)

    async def raw_content(self):
        return await self.content()

    async def content(self):
        if self._content is None:
            self._content = await self._httpx_response.aread()
        return self._content


class Request(transport.Request):
    """Requests request adapter.

    This class is used internally for making requests using asyncio transports
    in a consistent way. If you use :class:`AuthorizedSession` you do not need
    to construct or use this class directly.

    This class can be useful if you want to manually refresh a
    :class:`~google.auth.credentials.Credentials` instance::

        import google.auth.transport.httpx_requests

        request = google.auth.transport.httpx_requests.Request()

        credentials.refresh(request)

    Args:
        client (httpx.AsyncClient): The client to use to make HTTP requests.
            If not specified, a session will be created.

    .. automethod:: __call__
    """

    def __init__(self, client=None):
        self.client = client

    async def __call__(
        self,
        url,
        method="GET",
        body=None,
        headers=None,
        timeout=_DEFAULT_TIMEOUT,
        **kwargs,
    ):
        """
        Make an HTTP request using httpx.

        Args:
            url (str): The URL to be requested.
            method (Optional[str]):
                The HTTP method to use for the request. Defaults to 'GET'.
            body (Optional[bytes]):
                The payload or body in HTTP request.
            headers (Optional[Mapping[str, str]]):
                Request headers.
            timeout (Optional[int]): The number of seconds to wait for a
                response from the server. If not specified or if None, the
                requests default timeout will be used.
            kwargs: Additional arguments passed through to the underlying
                requests :meth:`requests.Session.request` method.

        Returns:
            google.auth.transport.Response: The HTTP response.

        Raises:
            google.auth.exceptions.TransportError: If any exception occurred.
        """

        try:
            if self.client is None:  # pragma: NO COVER
                self.client = httpx.AsyncClient()
            _helpers.request_log(_LOGGER, method, url, body, headers)
            response = await self.client.request(
                method, url, content=body, headers=headers, timeout=timeout, **kwargs
            )
            await _helpers_async.response_log_async(_LOGGER, response)
            return _CombinedResponse(response)

        except httpx.RequestError as caught_exc:
            new_exc = exceptions.TransportError(caught_exc)
            raise new_exc from caught_exc

        except asyncio.TimeoutError as caught_exc:
            new_exc = exceptions.TransportError(caught_exc)
            raise new_exc from caught_exc


class AuthorizedSession(httpx.AsyncClient):
    """This is an async implementation of the Authorized Session class. We util
    ize a httpx transport instance, and the interface mirrors the
    google.auth.transport.requests Authorized Session class, except for the
    change in the transport used in the async use case.

    A Requests Session class with credentials.

    This class is used to perform requests to API endpoints that require
    authorization::

        from google.auth.transport import httpx_requests

        async with httpx_requests.AuthorizedSession(credentials) as authed_session:
            response = await authed_session.request(
                'GET', 'https://www.googleapis.com/storage/v1/b')

    The underlying :meth:`request` implementation handles adding the
    credentials' headers to the request and refreshing credentials as needed.

    Args:
        credentials (google.auth.credentials.Credentials):
            The credentials to add to the request.
        refresh_status_codes (Sequence[int]): Which HTTP status codes indicate
            that credentials should be refreshed and the request should be
            retried.
        max_refresh_attempts (int): The maximum number of times to attempt to
            refresh the credentials and retry the request.
        refresh_timeout (Optional[int]): The timeout value in seconds for
            credential refresh HTTP requests.
        auth_request (google.auth.transport.httpx_requests.Request):
            (Optional) An instance of
            :class:`~google.auth.transport.httpx_requests.Request` used when
            refreshing credentials. If not passed,
            an instance of :class:`~google.auth.transport.httpx_requests.Request`
            is created.
        kwargs: Additional arguments passed through to the underlying
            ClientSession :meth:`httpx.ClientSession` object.
    """

    def __init__(
        self,
        credentials,
        refresh_status_codes=transport.DEFAULT_REFRESH_STATUS_CODES,
        max_refresh_attempts=transport.DEFAULT_MAX_REFRESH_ATTEMPTS,
        refresh_timeout=None,
        auth_request=None,
        auto_decompress=False,
        **kwargs,
    ):
        super(AuthorizedSession, self).__init__(**kwargs)
        self.credentials = credentials
        self._refresh_status_codes = refresh_status_codes
        self._max_refresh_attempts = max_refresh_attempts
        self._refresh_timeout = refresh_timeout
        self._is_mtls = False
        self._loop = asyncio.get_event_loop()
        self._refresh_lock = asyncio.Lock()
        self._auto_decompress = auto_decompress

        # Manage internal auth client lifecycle
        if auth_request is None:
            self._internal_auth_client = httpx.AsyncClient()
            self._auth_request = Request(self._internal_auth_client)
            self._owns_auth_client = True
        else:
            self._internal_auth_client = None
            self._auth_request = auth_request
            self._owns_auth_client = False

    async def aclose(self):
        """Close the underlying session and the internal auth session if created."""
        if self._owns_auth_client and self._internal_auth_client:
            await self._internal_auth_client.aclose()
        await super().aclose()

    async def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        max_allowed_time=None,
        timeout=_DEFAULT_TIMEOUT,
        auto_decompress=False,
        **kwargs,
    ) -> httpx.Response:

        """Implementation of Authorized Session httpx request.

        Args:
            method (str):
                The http request method used (e.g. GET, PUT, DELETE)
            url (str):
                The url at which the http request is sent.
            data (Optional[dict]): Dictionary, list of tuples, bytes, or file-l
                ike object to send in the body of the Request.
            headers (Optional[dict]): Dictionary of HTTP Headers to send with t
                he Request.
            timeout (Optional[Union[float, httpx.ClientTimeout]]):
                The amount of time in seconds to wait for the server response
                with each individual request. Can also be passed as an
                ``httpx.ClientTimeout`` object.
            max_allowed_time (Optional[float]):
                If the method runs longer than this, a ``Timeout`` exception is
                automatically raised. Unlike the ``timeout`` parameter, this
                value applies to the total method execution time, even if
                multiple requests are made under the hood.

                Mind that it is not guaranteed that the timeout error is raised
                at ``max_allowed_time``. It might take longer, for example, if
                an underlying request takes a lot of time, but the request
                itself does not timeout, e.g. if a large file is being
                transmitted. The timout error will be raised after such
                request completes.
        """

        # raise error if url does not start with http:// or https://
        if not url.startswith("http://") and not url.startswith("https://"):
            raise ValueError(
                "URL must start with http:// or https://. Got: {}".format(url)
            )

        # Headers come in as bytes which isn't expected behavior, the resumable
        # media libraries in some cases expect a str type for the header values
        # , but sometimes the operations return these in bytes types.
        if headers:
            for key in headers.keys():
                if type(headers[key]) is bytes:
                    headers[key] = headers[key].decode("utf-8")

        # Use a kwarg for this instead of an attribute to maintain
        # thread-safety.
        _credential_refresh_attempt = kwargs.pop("_credential_refresh_attempt", 0)
        # Make a copy of the headers. They will be modified by the credenti
        # als and we want to pass the original headers if we recurse.
        request_headers = headers.copy() if headers is not None else {}

        # Use the stored auth_request
        auth_request = (
            self._auth_request
            if timeout is None
            else functools.partial(self._auth_request, timeout=timeout)
        )

        remaining_time = max_allowed_time

        with _TimeoutGuard(remaining_time) as guard:
            # This modifies the request_headers in place.
            await self.credentials.before_request(
                auth_request, method, url, request_headers
            )

        with _TimeoutGuard(remaining_time) as guard:
            response = await super(AuthorizedSession, self).request(
                method,
                url,
                content=data,
                headers=request_headers,
                timeout=timeout,
                **kwargs,
            )

        remaining_time = guard.remaining_timeout

        if (
            response.status_code in self._refresh_status_codes
            and _credential_refresh_attempt < self._max_refresh_attempts
        ):

            _LOGGER.info(
                "Refreshing credentials due to a %s response. Attempt %s/%s.",
                response.status_code,
                _credential_refresh_attempt + 1,
                self._max_refresh_attempts,
            )

            # Do not apply the timeout unconditionally in order to not over
            # ride the _auth_request's default timeout.
            auth_request = (
                self._auth_request
                if timeout is None
                else functools.partial(self._auth_request, timeout=timeout)
            )

            with _TimeoutGuard(remaining_time) as guard:
                async with self._refresh_lock:
                    if inspect.iscoroutinefunction(self.credentials.refresh):
                        await self.credentials.refresh(auth_request)
                    else:
                        await self._loop.run_in_executor(
                            None, self.credentials.refresh, auth_request
                        )

            remaining_time = guard.remaining_timeout

            return await self.request(
                method,
                url,
                data=data,
                headers=headers,
                max_allowed_time=remaining_time,
                timeout=timeout,
                _credential_refresh_attempt=_credential_refresh_attempt + 1,
                **kwargs,
            )

        return response
