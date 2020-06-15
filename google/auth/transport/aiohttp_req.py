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

import google.auth

from google.oauth2 import service_account
from google.oauth2 import _client
from google.auth import exceptions
from google.auth import transport
import google.auth.transport._mtls_helper

import aiohttp

_OAUTH_SCOPES = [
    'https://www.googleapis.com/auth/appengine.apis',
    'https://www.googleapis.com/auth/userinfo.email',
]


#from aiohttp_requests import requests
#import requests


'''
try:
    import requests
except ImportError as caught_exc:  # pragma: NO COVER
    import six

    six.raise_from(
        ImportError(
            "The requests library is not installed, please install the "
            "requests package to use the requests transport."
        ),
        caught_exc,
    )


import requests.adapters  # pylint: disable=ungrouped-imports
import requests.exceptions  # pylint: disable=ungrouped-imports
from requests.packages.urllib3.util.ssl_ import (
    create_urllib3_context,
)  # pylint: disable=ungrouped-imports
import six  # pylint: disable=ungrouped-imports
'''

_LOGGER = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 120  # in seconds


class _Response(transport.Response):
    """Requests transport response adapter.

    Args:
        response (requests.Response): The raw Requests response.
    """

    def __init__(self, response):
        self._response = response

    @property
    def status(self):
        return self._response.status_code

    @property
    def headers(self):
        return self._response.headers

    @property
    def data(self):
        return self._response.content

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
        _LOGGER.debug("Making request: %s %s", method, url)
        async with self.session.request(method, url, data=body, headers=headers, timeout=timeout, **kwargs) as response:
            return await _Response(response)
        
        '''except requests.exceptions.RequestException as caught_exc:
            new_exc = exceptions.TransportError(caught_exc)
            six.raise_from(new_exc, caught_exc)
        '''


class AuthorizedSession(aiohttp.ClientSession):
    """

    documentation

    """

    def __init__(
        self,
        credentials,
        refresh_status_codes = transport.DEFAULT_REFRESH_STATUS_CODES,
        max_refresh_attempts = transport.DEFAULT_MAX_REFRESH_ATTEMPTS,
        refresh_timeout = None,
        auth_request = None
    ):
        super(AuthorizedSession, self).__init__()
        self.credentials = credentials
        self._refresh_status_codes = refresh_status_codes
        self._max_refresh_attempts = max_refresh_attempts
        self._refresh_timeout = refresh_timeout
        self._is_mtls = False
        self._auth_request = None
        self._loop = asyncio.get_event_loop()
        self._refresh_lock = asyncio.Lock() 

        if auth_request is None:
            auth_request_session = aiohttp.ClientSession()

            # Using an adapter to make HTTP requests robust to network errors.
            # This adapter retrys HTTP requests when network errors occur
            # and the requests seems safely retryable.
            
            #retry_adapter = requests.adapters.HTTPAdapter(max_retries=3)
            #auth_request_session.mount("https://", retry_adapter)

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
        max_allowed_time = None,
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

        #remaining_time = max_allowed_time

        #NOTE: Add the Timeout Guard context manager after finishing this implementation

        async with self._refresh_lock:
            await self._loop.run_in_executor(None, self.credentials.before_request, auth_request,
            method, url, request_headers)

        #remaining_time = guard.remaining_timeout

        response = await super(AuthorizedSession, self).request(
            method,
            url,
            data=data,
            headers=request_headers,
            timeout=timeout,
            **kwargs
        )

        #remaining_time = guard.remaining_timeout

        if (
            response.status in self._refresh_status_codes
            and _credential_refresh_attempt < self._max_refresh_attempts):

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

            async with self._refresh_lock:
                await self._loop.run_in_executor(None, self.credentials.refresh, auth_request)

            #remaining_time = guard.remaining_time
        
            return await self.request(
                method,
                url,
                data=data,
                headers=headers,
                max_allowed_time=remaining_time,
                timeout=timeout,
                _credential_refresh_attempt=_credential_refresh_attempt + 1,
                **kwargs)

        return response

    @property
    def is_mtls(self):
        """Indicates if the created SSL channel is mutual TLS."""
        return self._is_mtls


async def main():
    #breakpoint()
 
    credentials, project_id = google.auth.default()

    response = await AuthorizedSession(credentials).request('GET',"https://www.google.com")
    print(response.text)
    print(response.content)

if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())