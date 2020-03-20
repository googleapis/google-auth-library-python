# Lint as: python3
# Copyright 2016 Google Inc.
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

"""Credentials supporting asynchronous transports.

Overrides credentials base methods with asynchronous versions.
"""

import abc
from typing import Any, Mapping, Text

from google.auth import credentials
import google.auth.transport.aio


class Credentials(credentials.Credentials):
    """Base credentials class for asynchronous applications."""

    @abc.abstractmethod
    async def refresh(self, request: google.auth.transport.aio.Request):
        """Refreshes the access token.

        Args:
          request: HTTP request client.

        Raises:
          google.auth.exceptions.RefreshError: If credentials could not be
              refreshed.
        """

    async def before_request(
        self,
        request: google.auth.transport.aio.Request,
        method: Text,
        url: Text,
        headers: Mapping[Any, Any],
    ):
        """Performs credential-specific request pre-processing.

        Schedules the credentials to be refreshed if necessary, then calls
        :meth:`apply` to apply the token to the authentication header.


        Args:
          request: The object used to make HTTP requests.
          method: The request's HTTP method or the RPC method being invoked.
          url: The request's URI or the RPC service's URI.
          headers (Mapping): The request's headers.
        """
        del method
        del url
        if not self.valid:
            await self.refresh(request)
        self.apply(headers)
