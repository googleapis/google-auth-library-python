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

    The credentials are considered immutable except the tokens and the token
    expiry, which are updated after refresh. If you want to modify the quota
    project, use :meth:`with_quota_project` or ::

        credentials = credentials.with_quota_project('myproject-123')

    Reauth is disabled by default. To enable reauth, set the
    `enable_reauth_refresh` parameter to True in the constructor. Note that
    reauth feature is intended for gcloud to use only.
    If reauth is enabled, `pyu2f` dependency has to be installed in order to use security
    key reauth feature. Dependency can be installed via `pip install pyu2f` or `pip install
    google-auth[reauth]`.
    """

    def __init__(self, token):
        """
        Args:
            token (Optional(str)): The OAuth 2.0 access token. Can be None
                if refresh information is provided.
        """
        super(Credentials, self).__init__()
        self.token = token

    async def refresh(self, request):
        raise NotImplementedError("refresh is currently not supported for oauth2 access tokens.")