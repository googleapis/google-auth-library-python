# Copyright 2016 Google Inc. All rights reserved.
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

"""Service Accounts: JSON Web Token (JWT) Profile for OAuth 2.0

*Service accounts* are used for server-to-server communication, such as
interactions between a web application server and a Google service. The
service account belongs to your application instead of to an individual end
user. In contrast to other OAuth 2.0 profiles, no users are involved and your
application "acts" as the service account.

Typically, an application uses a service account when the application uses
Google APIs to work with its own data rather than a user's data. For example,
an application that uses Google Cloud Datastore for data persistence would use
a service account to authenticate its calls to the Google Cloud Datastore API.
However, an application that needs to access a user's Drive documents would
use the normal OAuth 2.0 profile.

Additionally, Google Apps domain administrators can grant service accounts
`domain-wide delegation`_ authority to access user data on behalf of users in
the domain.

This module implements the JWT Profile for OAuth 2.0 Authorization Grants
as defined by `RFC 7523`_ with particular support for how this RFC is
implemented in Google's infrastructure.

This profile uses a JWT to acquire an OAuth 2.0 access token. The JWT is used
in place of the usual authorization token returned during the standard
OAuth 2.0 Authorization Code grant. The JWT is only used for this purpose, as
the acquired access token is used as the bearer token when making requests
using these credentials.

This profile differs from normal OAuth 2.0 profile because no user consent
step is required. The use of the private key allows this profile to assert
identity directly.

This profile also differs from the :mod:`google.auth.jwt` authentication
because the JWT credentials use the JWT directly as the bearer token. This
profile instead only uses the JWT to obtain an OAuth 2.0 access token. The
obtained OAuth 2.0 access token is used as the bearer token.

TODO: Usage samples

Domain-wide delegation
----------------------

Domain-wide delegation allows a service account to access user data on
behalf of any user in a Google Apps domain without consent from the user.
For example, an application that uses the Google Calendar API to add events to
the calendars of all users in a Google Apps domain would use a service account
to access the Google Calendar API on behalf of users.

The Google Apps administrator must explicitly authorize the service account to
do this. This authorization step is referred to as "delegating domain-wide
authority" to a service account.

TODO: Usage samples

.. _RFC 7523: https://tools.ietf.org/html/rfc7523
"""

import datetime
import json

from six.moves import http_client
from six.moves import urllib

from google.auth import _helpers
from google.auth import crypt
from google.auth import credentials
from google.auth import exceptions
from google.auth import jwt
from google.auth import transport

_DEFAULT_TOKEN_LIFETIME_SECS = 3600  # 1 hour in sections
_JWT_TOKEN_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'


class Credentials(credentials.SigningCredentials,
                  credentials.ScopedCredentials,
                  credentials.Credentials):
    """Service account credentials

    Usually, you'll construct these credentials with
    one of the helper constructors::

        credentials = service_account.Credentials.from_service_account_file(
            'service-account.json')

    Or if you already have the service account file loaded::

        service_account_info = json.load(open('service_account.json'))
        credentials = service_account.Credentials.from_service_account_info(
            service_account_info)

    Both helper methods pass on arguments to the constructor, so you can
    specific the claims::

        credentials = service_account.Credentials.from_service_account_file(
            'service-account.json',
            audience='https://speech.googleapis.com',
            additional_claims={'meta': 'data'})

    You can also construct the credentials directly if you have a
    :class:`~google.auth.crypt.Signer` instance::

        credentials = service_account.Credentials(
            signer, issuer='your-issuer', subject='your-subject')

    The credentials are considered immutable. If you want to modify the scopes
    or the subject used for delegation, use :meth:`with_scopes` or
    :meth:`with_subject`::

        scoped_credentials = credentials.with_scopes(['email'])
        delegated_credentials = credentials.with_subject(subject)
    """

    def __init__(self, signer, service_account_email, token_uri, scopes=None,
                 subject=None, additional_claims=None):
        """Constructor

        Args:
            signer (google.auth.crypt.Signer): The signer used to sign JWTs.
            service_account_email (str): The service account's email.
            scopes (Union[str, Sequence]): Scopes to request.
            token_uri (str): The OAuth 2.0 Token URI.
            subject (str): For domain-wide delegation, the email address of the
                user to for which to request delegated access.
            additional_claims (Mapping): Any additional claims for the JWT
                assertion grant.
        """
        super(Credentials, self).__init__()
        self._scopes = scopes
        self._signer = signer
        self._service_account_email = service_account_email
        self._subject = subject
        self._token_uri = token_uri
        self._additional_claims = additional_claims or {}

    @classmethod
    def from_service_account_info(cls, info, **kwargs):
        """Creates a Credentials instance from parsed service account info.

        Args:
            info (Mapping): The service account info in Google format.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            google.auth.service_account.Credentials: The constructed
                credentials.
        """
        email = info['client_email']
        key_id = info['private_key_id']
        private_key = info['private_key']
        token_uri = info['token_uri']

        signer = crypt.Signer.from_string(private_key, key_id)

        return cls(
            signer, service_account_email=email, token_uri=token_uri, **kwargs)

    @classmethod
    def from_service_account_file(cls, filename, **kwargs):
        """Creates a Credentials instance from a service account json file.

        Args:
            filename (str): The path to the service account json file.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            google.auth.service_account.Credentials: The constructed
                credentials.
        """
        with open(filename, 'r') as json_file:
            info = json.load(json_file)
        return cls.from_service_account_info(info, **kwargs)

    @property
    def requires_scopes(self):
        """Checks if the credentials requires scopes.

        Returns:
            bool: True if there are no scopes set otherwise False.
        """
        return True if not self._scopes else False

    @_helpers.copy_docstring(credentials.ScopedCredentials)
    def with_scopes(self, scopes):
        return Credentials(
            self._signer,
            service_account_email=self._service_account_email,
            scopes=scopes,
            token_uri=self._token_uri,
            subject=self._subject,
            additional_claims=self._additional_claims.copy())

    def with_subject(self, subject):
        """Create a copy of these credentials with the specified subject.

        Args:
            subject (str): The subject claim.

        Returns:
            google.auth.service_account.Credentials: A new credentials
                instance.
        """
        return Credentials(
            self._signer,
            service_account_email=self._service_account_email,
            scopes=self._scopes,
            token_uri=self._token_uri,
            subject=subject,
            additional_claims=self._additional_claims.copy())

    def _make_authorization_grant_assertion(self):
        """Create the OAuth 2.0 assertion.

        This assertion is used during the OAuth 2.0 grant to acquire an
        access token.

        Returns:
            bytes: The authorization grant assertion.
        """
        now = _helpers.now()
        lifetime = datetime.timedelta(seconds=_DEFAULT_TOKEN_LIFETIME_SECS)
        expiry = now + lifetime

        payload = {
            'iat': _helpers.datetime_to_secs(now),
            'exp': _helpers.datetime_to_secs(expiry),
            # The issuer must be the service account email.
            'iss': self._service_account_email,
            # The audience must be the auth token endpoint's URI
            'aud': self._token_uri,
            'scope': _helpers.scopes_to_string(self._scopes)
        }

        # The subject can be a user email for domain-wide delegation.
        if self._subject:
            payload.setdefault('sub', self._subject)

        payload.update(self._additional_claims)

        token = jwt.encode(self._signer, payload)

        return token

    @_helpers.copy_docstring(credentials.Credentials)
    def refresh(self, http):
        assertion = self._make_authorization_grant_assertion()

        body = urllib.parse.urlencode({
            'assertion': assertion,
            'grant_type': _JWT_TOKEN_GRANT_TYPE,
        })

        headers = {
            'content-type': 'application/x-www-form-urlencoded',
        }

        response = transport.request(
            http, method='POST', url=self._token_uri, headers=headers,
            body=body)

        if response.status != http_client.OK:
            # Try to decode the response and extract details.
            try:
                error_data = json.loads(response.data.decode('utf-8'))
                error_details = ': '.join([
                    error_data['error'],
                    error_data.get('error_description')])
            # If not details could be extracted, use the response data.
            except (KeyError, ValueError):
                error_details = response.data

            raise exceptions.RefreshError(response.status, error_details)

        response_data = json.loads(response.data.decode('utf-8'))

        self.token = response_data['access_token']
        expires_in = response_data['expires_in']

        self.expiry = _helpers.now() + datetime.timedelta(seconds=expires_in)

    @_helpers.copy_docstring(credentials.SigningCredentials)
    def sign_bytes(self, message):
        return self._signer.sign(message)
