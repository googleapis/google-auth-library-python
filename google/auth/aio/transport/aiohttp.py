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

"""Transport adapter for Asynchronous HTTP Requests.
"""

import asyncio

try:
    import aiohttp
except ImportError as caught_exc:  # pragma: NO COVER
    raise ImportError(
        "The aiohttp library is not installed from please install the aiohttp package to use the aiohttp transport."
    ) from caught_exc
from google.auth import exceptions

_DEFAULT_TIMEOUT = 180  # in seconds


class Request:
    """Asynchronous Requests request adapter.

    This class is used internally for making requests using asyncio transports
    in a consistent way. If you use :class:`AuthorizedSession` you do not need
    to construct or use this class directly.

    This class can be useful if you want to manually refresh a
    :class:`~google.auth.aio.credentials.Credentials` instance::

        import google.auth.aio.transport.aiohttp

        request = google.auth.aio.transport.aiohttp.Request()

        await credentials.refresh(request)

    Args:
        session (aiohttp.ClientSession): An instance :class:`aiohttp.ClientSession` used
            to make HTTP requests. If not specified, a session will be created.

    .. automethod:: __call__
    """

    def __init__(self, session=None):
        # TODO(ohmayr): Evaluate if we want auto_decompress=False.
        # and if we want to update it in the passed in session.
        self.session = session or aiohttp.ClientSession(auto_decompress=False)

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
        Make an Asynchronous HTTP request using aiohttp.

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
                aiohttp :meth:`aiohttp.Session.request` method.

        Returns:
            google.auth.aio.transport.aiohttp.Response: The HTTP response.

        Raises:
            google.auth.exceptions.TransportError: If any exception occurred.
        """

        try:
            # TODO (ohmayr): verify the timeout type. We may need to pass
            # in aiohttp.ClientTimeout. Alternatively, we can incorporate
            # per request timeout within the timeout_guard context manager.
            response = await self.session.request(
                method, url, data=body, headers=headers, timeout=timeout, **kwargs
            )
            # TODO(ohmayr): Wrap this with Custom Response.
            return response

        except aiohttp.ClientError as caught_exc:
            new_exc = exceptions.TransportError(caught_exc)
            raise new_exc from caught_exc

        except asyncio.TimeoutError as caught_exc:

            # TODO(ohmayr): Raise Custom Timeout Error instead
            new_exc = exceptions.TransportError(caught_exc)
            raise new_exc from caught_exc

    async def close(self):
        """
        Close the underlying aiohttp session.
        """
        await self.session.close()
