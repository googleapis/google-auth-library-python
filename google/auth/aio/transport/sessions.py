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

from typing import Mapping, Optional

from google.auth.aio import transport
from google.auth.aio.credentials import Credentials

try:
    import aiohttp

    AIOHTTP_INSTALLED = True
except ImportError:
    AIOHTTP_INSTALLED = False

# TODO (ohmayr): Uncomment this when the timeout guard PR is merged.
# from google.auth.exceptions import TimeoutError

# TODO (ohmayr): Maybe move _DEFAULT_TIMEOUT to __init__.py
_DEFAULT_TIMEOUT = 180  # in seconds


class AuthorizedSession:

    """This is an asynchronous implementation of the Authorized Session class. We utilize an
    instance of a class that implements `google.auth.aio.transport.Request` configured by the caller
    or otherwise default to `google.auth.aio.transport.aiohttp.Request` if the external aiohttp package
    is installed.

    A Requests Session class with credentials.

    This class is used to perform asynchronous requests to API endpoints that require
    authorization::

        import aiohttp
        from google.auth.aio.transport import sessions
        
        async with sessions.AuthorizedSession(credentials) as authed_session:
            response = await authed_session.request(
                'GET', 'https://www.googleapis.com/storage/v1/b')

    The underlying :meth:`request` implementation handles adding the
    credentials' headers to the request and refreshing credentials as needed.

    Args:
        credentials (google.auth.aio.credentials.Credentials):
            The credentials to add to the request.
        auth_request (google.auth.aio.transport.Request):
            (Optional) An instance of a class that implements
            :class:`~google.auth.aio.transport.Request` used to make requests
            and refresh credentials. If not passed,
            an instance of :class:`~google.auth.aio.transport.aiohttp.Request`
            is created.

    Raises:
        ValueError: If `auth_request` is `None` and the external package `aiohttp` is not installed.
    """

    def __init__(
        self, credentials: Credentials, auth_request: transport.Request = None
    ):
        self._auth_request = auth_request or (
            AIOHTTP_INSTALLED and transport.aiohttp.Request()
        )
        if not self._auth_request:
            raise ValueError(
                "`auth_request` must either be configured or the external package `aiohttp` must be installed to use the default value."
            )

        self._credentials = credentials

    async def request(
        self,
        method: str,
        url: str,
        data: bytes = None,
        headers: Mapping[str, str] = None,
        max_allowed_time: Optional[
            float
        ] = None,  # TODO (ohmayr): set a default value for timeout.
        timeout: Optional[float] = _DEFAULT_TIMEOUT,
        **kwargs,
    ) -> transport.Response:

        """
        Args:
                method (str): The http method used to make the request.
                url (str): The URI to be requested.
                data (bytes): The payload or body in HTTP request.
                headers (Mapping[str, str]): Request headers.       
                timeout (Optional[float]):
                The amount of time in seconds to wait for the server response
                with each individual request.
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
        
        Raises:
        # TODO (ohmayr): populate this.

        Returns:
        # TODO (ohmayr): populate this.

        # TODO (ohmayr): Investigate if this is required.
        # I think it is reasonable to agree on a strict type for headers and 
        # let the caller handle any translation.
            if headers:
                for key in headers.keys():
                    if type(headers[key]) is bytes:
                        headers[key] = headers[key].decode("utf-8")

        # Headers come in as bytes which isn't expected behavior, the resumable
        # media libraries in some cases expect a str type for the header values,
        # but sometimes the operations return these in bytes types.
        """

        if not isinstance(self._credentials, Credentials):
            raise ValueError(
                "The configured credentials are invalid and must be of type `google.auth.aio.credentials.Credentials`"
            )

        _credentials_refresh_attempt = 0
        response = None

        try:
            async with timeout_guard(max_allowed_time) as with_timeout:
                while (
                    _credentials_refresh_attempt
                    < transport.DEFAULT_MAX_REFRESH_ATTEMPTS
                ):
                    if self.credentials and not _credentials_refresh_attempt:
                        await with_timeout(
                            self.credentials.before_request(None, method, url, headers)
                        )

                    response = await with_timeout(
                        self._auth_request(
                            url, method, data, headers, timeout, **kwargs
                        )
                    )
                    if response.status_code in transport.DEFAULT_REFRESH_STATUS_CODES:
                        await with_timeout(self.credentials.refresh(self._auth_request))
                        _credentials_refresh_attempt += 1
                    else:
                        return response

        except TimeoutError as exc:
            raise exc

        return response

    async def get(
        self,
        url: str,
        data: bytes = None,
        headers: Mapping[str, str] = None,
        max_allowed_time: Optional[
            float
        ] = None,  # TODO (ohmayr): set a default value for timeout.
        timeout: Optional[float] = _DEFAULT_TIMEOUT,
        **kwargs,
    ) -> transport.Response:
        return await self.request(
            "get", url, data, headers, max_allowed_time, timeout, **kwargs
        )

    async def post(
        self,
        url: str,
        data: bytes = None,
        headers: Mapping[str, str] = None,
        max_allowed_time: Optional[
            float
        ] = None,  # TODO (ohmayr): set a default value for timeout.
        timeout: Optional[float] = _DEFAULT_TIMEOUT,
        **kwargs,
    ) -> transport.Response:
        return await self.request(
            "post", url, data, headers, max_allowed_time, timeout, **kwargs
        )

    async def put(
        self,
        url: str,
        data: bytes = None,
        headers: Mapping[str, str] = None,
        max_allowed_time: Optional[
            float
        ] = None,  # TODO (ohmayr): set a default value for timeout.
        timeout: Optional[float] = _DEFAULT_TIMEOUT,
        **kwargs,
    ) -> transport.Response:
        return await self.request(
            "put", url, data, headers, max_allowed_time, timeout, **kwargs
        )

    async def patch(
        self,
        url: str,
        data: bytes = None,
        headers: Mapping[str, str] = None,
        max_allowed_time: Optional[
            float
        ] = None,  # TODO (ohmayr): set a default value for timeout.
        timeout: Optional[float] = _DEFAULT_TIMEOUT,
        **kwargs,
    ) -> transport.Response:
        return await self.request(
            "patch", url, data, headers, max_allowed_time, timeout, **kwargs
        )

    async def delete(
        self,
        url: str,
        data: bytes = None,
        headers: Mapping[str, str] = None,
        max_allowed_time: Optional[
            float
        ] = None,  # TODO (ohmayr): set a default value for timeout.
        timeout: Optional[float] = _DEFAULT_TIMEOUT,
        **kwargs,
    ) -> transport.Response:
        return await self.request(
            "delete", url, data, headers, max_allowed_time, timeout, **kwargs
        )

    async def close(self) -> None:
        """
        Close the underlying auth request session.
        """
        if self._auth_request:
            await self._auth_request.close()
