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

"""Asynchronous service account interface.

Service accounts that support asynchronous HTTP clients.
"""

from google.auth.aio import credentials
import google.auth.transport.aio
from google.oauth2 import service_account
from google.oauth2.aio import _client


class Credentials(credentials.Credentials, service_account.Credentials):
    """Service account credentials for asynchronous applications."""

    async def refresh(self, request: google.auth.transport.aio.Request):
        """Refreshes the access token.

        Args:
          request: HTTP request client.

        Raises:
          google.auth.exceptions.RefreshError: If credentials could not be
              refreshed.
        """
        assertion = self._make_authorization_grant_assertion()
        access_token, expiry, _ = await _client.jwt_grant(
            request, self._token_uri, assertion
        )
        self.token = access_token
        self.expiry = expiry
