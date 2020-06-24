# Copyright 2016 Google LLC
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

"""Transport adapter for Async HTTP (aiohttp)."""

from __future__ import absolute_import

import asyncio
import functools
import logging
import numbers
import time

# import requests
import aiohttp

# import requests.adapters
# from requests.packages.urllib3.util.ssl_ import create_urllib3_context
import six


# from google.oauth2 import service_account
# from google.oauth2 import _client

import google.auth
from google.auth import exceptions
from google.auth import transport
import google.auth.transport._mtls_helper


_OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/appengine.apis",
    "https://www.googleapis.com/auth/userinfo.email",
]

_LOGGER = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 120  # in seconds


class _Response(transport.Response):
    """Requests transport response adapter.

    Args:
        response (requests.Response): The raw Requests response.
    """

    def __init__(self, response):
        self.response = response

    @property
    def status(self):
        return self.response.status

    @property
    def headers(self):
        return self.response.headers

    @property
    def data(self):
        return self.response.content


class TimeoutGuard(object):
    """A context manager raising an error if the suite execution took too long.

    Args:
        timeout ([Union[None, float, Tuple[float, float]]]):
            The maximum number of seconds a suite can run without the context
            manager raising a timeout exception on exit. If passed as a tuple,
            the smaller of the values is taken as a timeout. If ``None``, a
            timeout error is never raised.
        timeout_error_type (Optional[Exception]):
            The type of the error to raise on timeout. Defaults to
            :class:`requests.exceptions.Timeout`.
    """

    def __init__(self, timeout, timeout_error_type=asyncio.TimeoutError):
        self._timeout = timeout
        self.remaining_timeout = timeout
        self._timeout_error_type = timeout_error_type

    def __enter__(self):
        self._start = time.time()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_value:
            return  # let the error bubble up automatically

        if self._timeout is None:
            return  # nothing to do, the timeout was not specified

        elapsed = time.time() - self._start
        deadline_hit = False

        if isinstance(self._timeout, numbers.Number):
            self.remaining_timeout = self._timeout - elapsed
            deadline_hit = self.remaining_timeout <= 0
        else:
            self.remaining_timeout = tuple(x - elapsed for x in self._timeout)
            deadline_hit = min(self.remaining_timeout) <= 0

        if deadline_hit:
            raise self._timeout_error_type()


class Request(transport.Request):
    """Requests request adapter.

    This class is used internally for making requests using various transports
    in a consistent way. If you use :class:`AuthorizedSession` you do not need
    to construct or use this class directly.

    This class can be useful if you want to manually refresh a
    :class:`~google.auth.credentials.Credentials` instance::

        import google.auth.transport.requests
        import requests

        request = google.auth.transport.requests.Request()

        credentials.refresh(request)

    Args:
        session (requests.Session): An instance :class:`requests.Session` used
            to make HTTP requests. If not specified, a session will be created.

    .. automethod:: __call__
    """

    def __init__(self, session=None):
        if not session:
            session = aiohttp.ClientSession()
        self.session = session

    async def __call__(
        self,
        url,
        method="GET",
        body=None,
        headers=None,
        timeout=_DEFAULT_TIMEOUT,
        **kwargs
    ):
        """Make an HTTP request using aiohttp.

        Args:
            url (str): The URI to be requested.
            method (str): The HTTP method to use for the request. Defaults
                to 'GET'.
            body (bytes): The payload / body in HTTP request.
            headers (Mapping[str, str]): Request headers.
            timeout (Optional[int]): The number of seconds to wait for a
                response from the server. If not specified or if None, the
                requests default timeout will be used.
            kwargs: Additional arguments passed through to the underlying
                requests :meth:`~requests.Session.request` method.

        Returns:
            google.auth.transport.Response: The HTTP response.

        Raises:
            google.auth.exceptions.TransportError: If any exception occurred.
        """
        try:
            _LOGGER.debug("Making request: %s %s", method, url)
            response = await self.session.request(
                method, url, data=body, headers=headers, timeout=timeout, **kwargs
            )
            return _Response(response)

        except aiohttp.ClientError as caught_exc:
            new_exc = exceptions.TransportError(caught_exc)
            six.raise_from(new_exc, caught_exc)

        except asyncio.TimeoutError as caught_exc1:
            new_exc1 = exceptions.TransportError(caught_exc1)
            six.raise_from(new_exc1, caught_exc1)


'''
class _MutualTlsAdapter(requests.adapters.HTTPAdapter):
    """
    A TransportAdapter that enables mutual TLS.

    Args:
        cert (bytes): client certificate in PEM format
        key (bytes): client private key in PEM format

    Raises:
        ImportError: if certifi or pyOpenSSL is not installed
        OpenSSL.crypto.Error: if client cert or key is invalid
    """

    def __init__(self, cert, key):
        import certifi
        from OpenSSL import crypto
        import urllib3.contrib.pyopenssl

        urllib3.contrib.pyopenssl.inject_into_urllib3()

        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

        ctx_poolmanager = create_urllib3_context()
        ctx_poolmanager.load_verify_locations(cafile=certifi.where())
        ctx_poolmanager._ctx.use_certificate(x509)
        ctx_poolmanager._ctx.use_privatekey(pkey)
        self._ctx_poolmanager = ctx_poolmanager

        ctx_proxymanager = create_urllib3_context()
        ctx_proxymanager.load_verify_locations(cafile=certifi.where())
        ctx_proxymanager._ctx.use_certificate(x509)
        ctx_proxymanager._ctx.use_privatekey(pkey)
        self._ctx_proxymanager = ctx_proxymanager

        super(_MutualTlsAdapter, self).__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx_poolmanager
        super(_MutualTlsAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx_proxymanager
        return super(_MutualTlsAdapter, self).proxy_manager_for(*args, **kwargs)
'''


class AuthorizedSession(aiohttp.ClientSession):
    """

    documentation

    """

    def __init__(
        self,
        credentials,
        refresh_status_codes=transport.DEFAULT_REFRESH_STATUS_CODES,
        max_refresh_attempts=transport.DEFAULT_MAX_REFRESH_ATTEMPTS,
        refresh_timeout=None,
        auth_request=None,
    ):
        super(AuthorizedSession, self).__init__()
        self.credentials = credentials
        self._refresh_status_codes = refresh_status_codes
        self._max_refresh_attempts = max_refresh_attempts
        self._refresh_timeout = refresh_timeout
        self._is_mtls = False
        self._auth_request = auth_request
        self._loop = asyncio.get_event_loop()
        self._refresh_lock = asyncio.Lock()

        if auth_request is None:
            auth_request_session = aiohttp.ClientSession()

            # Using an adapter to make HTTP requests robust to network errors.
            # This adapter retrys HTTP requests when network errors occur
            # and the requests seems safely retryable.

            # retry_adapter = requests.adapters.HTTPAdapter(max_retries=3)
            # auth_request_session.mount("https://", retry_adapter)

            # Do not pass `self` as the session here, as it can lead to
            # infinite recursion.
            auth_request = Request(auth_request_session)

            # Request instance used by internal methods (for example,
            # credentials.refresh).

            self._auth_request = auth_request

    def configure_mtls_channel(self, client_cert_callback=None):
        """Configure the client certificate and key for SSL connection.
        If client certificate and key are successfully obtained (from the given
        client_cert_callback or from application default SSL credentials), a
        :class:`_MutualTlsAdapter` instance will be mounted to "https://" prefix.
        Args:
            client_cert_callback (Optional[Callable[[], (bytes, bytes)]]):
                The optional callback returns the client certificate and private
                key bytes both in PEM format.
                If the callback is None, application default SSL credentials
                will be used.
        Raises:
            google.auth.exceptions.MutualTLSChannelError: If mutual TLS channel
                creation failed for any reason.
        """
        try:
            import OpenSSL
        except ImportError as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(caught_exc)
            six.raise_from(new_exc, caught_exc)

        try:
            self._is_mtls, cert, key = google.auth.transport._mtls_helper.get_client_cert_and_key(
                client_cert_callback
            )

            if self._is_mtls:
                mtls_adapter = _MutualTlsAdapter(cert, key)
                self.mount("https://", mtls_adapter)
        except (
            exceptions.ClientCertError,
            ImportError,
            OpenSSL.crypto.Error,
        ) as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(caught_exc)
            six.raise_from(new_exc, caught_exc)

    async def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        max_allowed_time=None,
        timeout=_DEFAULT_TIMEOUT,
        **kwargs
    ):

        # Use a kwarg for this instead of an attribute to maintain
        # thread-safety.
        _credential_refresh_attempt = kwargs.pop("_credential_refresh_attempt", 0)
        # Make a copy of the headers. They will be modified by the credentials
        # and we want to pass the original headers if we recurse.
        request_headers = headers.copy() if headers is not None else {}

        # Do not apply the timeout unconditionally in order to not override the
        # _auth_request's default timeout.

        auth_request = (
            self._auth_request
            if timeout is None
            else functools.partial(self._auth_request, timeout=timeout)
        )

        remaining_time = max_allowed_time

        with TimeoutGuard(remaining_time) as guard:
            async with self._refresh_lock:
                await self._loop.run_in_executor(
                    None,
                    self.credentials.async_before_request,
                    auth_request,
                    method,
                    url,
                    request_headers,
                )

        remaining_time = guard.remaining_timeout

        with TimeoutGuard(remaining_time) as guard:
            response = await super(AuthorizedSession, self).request(
                method,
                url,
                data=data,
                headers=request_headers,
                timeout=timeout,
                **kwargs
            )

        remaining_time = guard.remaining_timeout

        if (
            response.status in self._refresh_status_codes
            and _credential_refresh_attempt < self._max_refresh_attempts
        ):

            _LOGGER.info(
                "Refreshing credentials due to a %s response. Attempt %s/%s.",
                response.status,
                _credential_refresh_attempt + 1,
                self._max_refresh_attempts,
            )

            # Do not apply the timeout unconditionally in order to not override the
            # _auth_request's default timeout.
            auth_request = (
                self._auth_request
                if timeout is None
                else functools.partial(self._auth_request, timeout=timeout)
            )

            with TimeoutGuard(remaining_time) as guard:
                async with self._refresh_lock:
                    await self._loop.run_in_executor(
                        None, self.credentials.refresh, auth_request
                    )

            remaining_time = guard.remaining_time

            return await self.request(
                method,
                url,
                data=data,
                headers=headers,
                max_allowed_time=remaining_time,
                timeout=timeout,
                _credential_refresh_attempt=_credential_refresh_attempt + 1,
                **kwargs
            )

        return response

    @property
    def is_mtls(self):
        """Indicates if the created SSL channel is mutual TLS."""
        return self._is_mtls


async def main():
    # breakpoint()

    credentials, project_id = google.auth.default()

    async with AuthorizedSession(credentials) as session:
        response = await session.request("GET", "https://www.google.com")

        print(response.status)
        print(response.text)
        print(response.content)

        await session.close()


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
