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

"""Transport adapter for http.client, for internal use only."""

import http.client as http_client
import logging
import socket
import urllib

from rewired.auth import exceptions

_LOGGER = logging.getLogger(__name__)


class Response:
    """http.client transport response adapter."""

    def __init__(self, response):
        self._status = response.status
        self._headers = {key.lower(): value for key, value in response.getheaders()}
        self._data = response.read()

    @property
    def status(self):
        return self._status

    @property
    def headers(self):
        return self._headers

    @property
    def data(self):
        return self._data


class Request:
    """http.client transport request adapter."""

    def __call__(
        self, url, method="GET", body=None, headers=None, timeout=None, **kwargs
    ):
        if timeout is None:
            timeout = socket._GLOBAL_DEFAULT_TIMEOUT

        if headers is None:
            headers = {}

        parts = urllib.parse.urlsplit(url)
        path = urllib.parse.urlunsplit(
            ("", "", parts.path, parts.query, parts.fragment)
        )

        if parts.scheme != "http":
            raise exceptions.TransportError(
                f"http.client transport only supports the http scheme, {parts.scheme} was specified"
            )

        connection = http_client.HTTPConnection(parts.netloc, timeout=timeout)

        try:
            _LOGGER.debug("Making request: %s %s", method, url)

            connection.request(method, path, body=body, headers=headers, **kwargs)
            response = connection.getresponse()
            return Response(response)

        except (http_client.HTTPException, socket.error) as caught_exc:
            raise exceptions.TransportError(caught_exc) from caught_exc

        finally:
            connection.close()
