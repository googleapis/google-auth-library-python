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

"""OAuth 2.0 Asynchronous Credentials.

This module provides credentials based on OAuth 2.0 access and refresh tokens.
These credentials usually access resources on behalf of a user (resource
owner).

Specifically, this is intended to use access tokens acquired using the
`Authorization Code grant`_ and can refresh those tokens using a
optional `refresh token`_.

Obtaining the initial access and refresh token is outside of the scope of this
module. Consult `rfc6749 section 4.1`_ for complete details on the
Authorization Code grant flow.

.. _Authorization Code grant: https://tools.ietf.org/html/rfc6749#section-1.3.1
.. _refresh token: https://tools.ietf.org/html/rfc6749#section-6
.. _rfc6749 section 4.1: https://tools.ietf.org/html/rfc6749#section-4.1
"""

from google.auth.aio import credentials


class Credentials(credentials.Credentials):
    """Asynchronous Credentials using OAuth 2.0 access and refresh tokens.

    """

    def __init__(self):
        super(Credentials, self).__init__()

    async def refresh(self, request):
        raise NotImplementedError("refresh is currently not supported for OAuth 2.0 access tokens.")


class CredentialsBuilder():
    """Builder class for constructing Asynchronous Credentials using OAuth 2.0 access and refresh tokens.
    
    """

    def __init__(self):
        self.credentials = Credentials()
    
    def setToken(self, token):
        """Sets the OAuth 2.0 access token.

        Args:
            token (str): The OAuth 2.0 access token.
        """
        self.credentials.token = token
        return self

    # TODO(ohmayr): Implement this once expiry is added to the base credentials.
    # def setExpiry(self, expiry=None):
    #     self.credentials.expiry = expiry
    #     return self
    
    def build(self):
        """Constructs and returns google.oauth2.aio.credentials.Credentials object.

        Returns:
            google.oauth2.aio.credentials.Credentials: The constructed google.oauth2.aio.credentials.Credentials object.
        """
        return self.credentials
