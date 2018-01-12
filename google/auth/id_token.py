# Copyright 2018 Google Inc.
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

import datetime
import six

from google.auth import _helpers
from google.auth import exceptions
from google.auth import jwt

from google.oauth2._client import _JWT_GRANT_TYPE
from google.oauth2._client import _token_endpoint_request


_GOOGLE_ID_TOKEN_URI = 'https://www.googleapis.com/oauth2/v4/token'


def id_token_jwt_grant(request, token_uri, assertion):
    """Exchange a JWT token signed by a service account for a Google ID token.

    Args:
        request (google.auth.transport.Request): A callable used to make
            HTTP requests.
        token_uri (str): The OAuth 2.0 authorizations server's token endpoint
            URI.
        assertion (str): JWT token signed by a service account.
            The assertion must include a 'target_audience' claim.

    Returns:
        Tuple[str, Optional[datetime], Mapping[str, str]]: The Google ID token,
            expiration, and the JWT claims.

    Raises:
        google.auth.exceptions.RefreshError: If the token endpoint returned
            an error.
    """
    body = {
        'assertion': assertion,
        'grant_type': _JWT_GRANT_TYPE,
    }

    response_data = _token_endpoint_request(request, token_uri, body)

    try:
        id_token = response_data['id_token']
    except KeyError as caught_exc:
        new_exc = exceptions.RefreshError(
            'No ID token in response.', response_data)
        six.raise_from(new_exc, caught_exc)

    payload = jwt.decode(id_token, verify=False)
    expiry = datetime.datetime.fromtimestamp(payload['exp'])

    return id_token, expiry, payload


class Credentials(jwt.Credentials):
    """Credentials that use a Google ID token as the bearer token."""

    def _make_jwt(self, request):
        """Make a Google ID JWT token.

        The Google ID token is issued by https://accounts.google.com.

        Returns:
            Tuple[bytes, datetime]: The encoded JWT and the expiration.
        """
        now = _helpers.utcnow()
        lifetime = datetime.timedelta(seconds=self._token_lifetime)
        expiry = now + lifetime

        payload = {
            'iss': self._issuer,
            'sub': self._subject,
            'iat': _helpers.datetime_to_secs(now),
            'exp': _helpers.datetime_to_secs(expiry),
            'aud': _GOOGLE_ID_TOKEN_URI,
            'target_audience': self._audience,
        }

        payload.update(self._additional_claims)

        signed_jwt = jwt.encode(self._signer, payload)

        id_token, expiry, _ = id_token_jwt_grant(request, _GOOGLE_ID_TOKEN_URI, signed_jwt)

        return id_token, expiry

    def refresh(self, request):
        """Refreshes the access token.

        Args:
            request (google.auth.transport.Request): Unused.
        """
        self.token, self.expiry = self._make_jwt(request)
