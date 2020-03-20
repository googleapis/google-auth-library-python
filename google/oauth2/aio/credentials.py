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

"""Asynchronous OAuth 2.0 Credentials.

This module extends google.oauth2.credentials with an interface for use with
async transports.
"""

from google.auth import exceptions
import google.auth.aio.credentials as aio_credentials
import google.auth.transport.aio
from google.oauth2.aio import _client
import google.oauth2.credentials as oauth2_credentials


class Credentials(aio_credentials.Credentials, oauth2_credentials.Credentials):
    """Credentials using OAuth 2.0 access and refresh tokens."""

    async def refresh(self, request: google.auth.transport.aio.Request):
        """Refreshes the access token.

        Args:
          request: HTTP request client.

        Raises:
          google.auth.exceptions.RefreshError: If credentials could not be
              refreshed.
        """
        if (
            self._refresh_token is None
            or self._token_uri is None
            or self._client_id is None
            or self._client_secret is None
        ):
            raise exceptions.RefreshError(
                "The credentials do not contain the necessary fields need to "
                "refresh the access token. You must specify refresh_token, "
                "token_uri, client_id, and client_secret."
            )

        access_token, refresh_token, expiry, grant_response = await _client.refresh_grant(
            request,
            self._token_uri,
            self._refresh_token,
            self._client_id,
            self._client_secret,
        )

        self.token = access_token
        self.expiry = expiry
        self._refresh_token = refresh_token
        self._id_token = grant_response.get("id_token")
