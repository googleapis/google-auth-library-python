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

"""Transport adapter for Async HTTP (aiohttp)."""

from __future__ import absolute_import

import asyncio
import functools
import logging
import time


import aiohttp
import six


from google.auth import exceptions
from google.auth import transport


_OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/appengine.apis",
    "https://www.googleapis.com/auth/userinfo.email",
]

_LOGGER = logging.getLogger(__name__)

# Timeout can be re-defined depending on async requirement. Currently made 60s more than
# sync timeout.
_DEFAULT_TIMEOUT = 180  # in seconds


class _Response(transport.Response):
    """
    Requests transport response adapter.

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

    This class is used internally for making requests using asyncio transports
    in a consistent way. If you use :class:`AuthorizedSession` you do not need
    to construct or use this class directly.

    This class can be useful if you want to manually refresh a
    :class:`~google.auth.credentials.Credentials` instance::

        import google.auth.transport.aiohttp_req
        import aiohttp

        request = google.auth.transport.aiohttp_req.Request()

        credentials.refresh(request)

    Args:
        session (aiohttp.ClientSession): An instance :class: aiohttp.ClientSession used
            to make HTTP requests. If not specified, a session will be created.

    .. automethod:: __call__
    """

    def __init__(self, session=None):
        '''
        self.session = None
        if not session:
            session = aiohttp.ClientSession()
        '''
        self.session = None

    async def __call__(
        self,
        url,
        method="GET",
        body=None,
        headers=None,
        timeout=_DEFAULT_TIMEOUT,
        **kwargs
    ):
        """
        Make an HTTP request using aiohttp.

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
        
        if self.session is None:
            self.session = aiohttp.ClientSession(raise_for_status=True)

        try:
            _LOGGER.debug("Making request: %s %s", method, url)
            response = await self.session.request(
                method, url, data=body, headers=headers, timeout=timeout, **kwargs
            )
            return _Response(response)

        except aiohttp.ClientError as caught_exc:
            new_exc = exceptions.TransportError(caught_exc)
            six.raise_from(new_exc, caught_exc)

        except asyncio.TimeoutError as caught_exc:
            new_exc = exceptions.TransportError(caught_exc)
            six.raise_from(new_exc, caught_exc)


class AuthorizedSession(aiohttp.ClientSession):
    """This is an async implementation of the Authorized Session class. We utilize an
    aiohttp transport instance, and the interface mirrors the google.auth.transport.requests
    Authorized Session class, except for the change in the transport used in the async use case.

    A Requests Session class with credentials.

    This class is used to perform requests to API endpoints that require
    authorization::

        import google.auth.transport.aiohttp_req

        async with aiohttp_req.AuthorizedSession(credentials) as authed_session:
            response = await authed_session.request(
                'GET', 'https://www.googleapis.com/storage/v1/b')

    The underlying :meth:`request` implementation handles adding the
    credentials' headers to the request and refreshing credentials as needed.

    Args:
        credentials (google.auth.credentials.Credentials): The credentials to
            add to the request.
        refresh_status_codes (Sequence[int]): Which HTTP status codes indicate
            that credentials should be refreshed and the request should be
            retried.
        max_refresh_attempts (int): The maximum number of times to attempt to
            refresh the credentials and retry the request.
        refresh_timeout (Optional[int]): The timeout value in seconds for
            credential refresh HTTP requests.
        auth_request (google.auth.transport.aiohttp_req.Request):
            (Optional) An instance of
            :class:`~google.auth.transport.aiohttp_req.Request` used when
            refreshing credentials. If not passed,
            an instance of :class:`~google.auth.transport.aiohttp_req.Request`
            is created.
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
        self._auth_request_session = None
        self._loop = asyncio.get_event_loop()
        self._refresh_lock = asyncio.Lock()

        if auth_request is None:
            self._auth_request_session = aiohttp.ClientSession()
            auth_request = Request(self._auth_request_session)
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
        """

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
            await self.credentials.before_request(auth_request, method, url, request_headers)

        with TimeoutGuard(remaining_time) as guard:
            temp_session = super(AuthorizedSession, self)
            response = await temp_session.request(
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

            remaining_time = guard.remaining_timeout

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

        await self._auth_request_session.close()

        return response

'''
async def main():
    #breakpoint() 
    token = 'https://oauth2.googleapis.com/token'
    headers = {'content-type': 'application/x-www-form-urlencoded'}
    body = b'assertion=eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiZTIwMjIyZTViYzQzZWQ5YTIyZjNjNzMwYTY5NjczOTZjYWJhYTM4NyJ9.eyJpYXQiOiAxNTk1MjU5NzI2LCAiZXhwIjogMTU5NTI2MzMyNiwgImlzcyI6ICJhbmlydWRoYmFkZGVwdS1sb2NhbC1kZXZAYW5pcnVkaGJhZGRlcHUtMjAyMC1pbnRlcm4uaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iLCAiYXVkIjogImh0dHBzOi8vb2F1dGgyLmdvb2dsZWFwaXMuY29tL3Rva2VuIiwgInNjb3BlIjogImVtYWlsIHByb2ZpbGUifQ.aNq5PAaz_3voWR4tIcrEzSx-nTy4EC4BDqf7mtG4xfCeMkt9A0NTSM4Tw5ExlheEYatmKPAeGKJFJ6VM9fAFeAvNbLSQPYhqxOMaNwL6HPC66XLqEYya2Tf0g7eIgPnha_AvLHlNShgBCJIlgyWAVOo6f2Tm--kByztpVadlbZjAPEhnqy05Y2dy4MlQSShRf2kN0DVcumaxQFUoHD4p27HMejs9L3z961Qxsw_dpJmcGuz2tPPlEKOlD8kdVzUOTAXi4yt4zg8m6QMk5hPhkHzknSvzV47j0q6NKyL3Q52SxxPuatpWwADrtkEySlhgfi0P3x7Y4Osv7oAxWeYQAQ&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer'
    credentials = service_account.Credentials.from_service_account_file(
            'service_account.json')
    session = AuthorizedSession(credentials)
    #breakpoint()
    response = await session.request(method="POST", url=token, headers=headers, body=body)
    print(response.text)

if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main()) 
'''