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

"""OAuth 2.0 Credentials.

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

import io
import json
import copy

import six

from google.auth import _helpers
from google.auth import credentials
from google.auth import exceptions
from google.oauth2 import _client


# The Google OAuth 2.0 token endpoint. Used for authorized user credentials.
_GOOGLE_OAUTH2_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'


class Credentials(credentials.ReadOnlyScoped, credentials.Credentials):
    """Credentials using OAuth 2.0 access and refresh tokens."""

    def __init__(self, token, refresh_token=None, id_token=None,
                 token_uri=None, client_id=None, client_secret=None,
                 scopes=None):
        """
        Args:
            token (Optional(str)): The OAuth 2.0 access token. Can be None
                if refresh information is provided.
            refresh_token (str): The OAuth 2.0 refresh token. If specified,
                credentials can be refreshed.
            id_token (str): The Open ID Connect ID Token.
            token_uri (str): The OAuth 2.0 authorization server's token
                endpoint URI. Must be specified for refresh, can be left as
                None if the token can not be refreshed.
            client_id (str): The OAuth 2.0 client ID. Must be specified for
                refresh, can be left as None if the token can not be refreshed.
            client_secret(str): The OAuth 2.0 client secret. Must be specified
                for refresh, can be left as None if the token can not be
                refreshed.
            scopes (Sequence[str]): The scopes used to obtain authorization.
                This parameter is used by :meth:`has_scopes`. OAuth 2.0
                credentials can not request additional scopes after
                authorization. The scopes must be derivable from the refresh
                token if refresh information is provided (e.g. The refresh
                token scopes are a superset of this or contain a wild card
                scope like 'https://www.googleapis.com/auth/any-api').
        """
        super(Credentials, self).__init__()
        self.token = token
        self._refresh_token = refresh_token
        self._id_token = id_token
        self._scopes = scopes
        self._token_uri = token_uri
        self._client_id = client_id
        self._client_secret = client_secret

    @property
    def refresh_token(self):
        """Optional[str]: The OAuth 2.0 refresh token."""
        return self._refresh_token

    @property
    def token_uri(self):
        """Optional[str]: The OAuth 2.0 authorization server's token endpoint
        URI."""
        return self._token_uri

    @property
    def id_token(self):
        """Optional[str]: The Open ID Connect ID Token.

        Depending on the authorization server and the scopes requested, this
        may be populated when credentials are obtained and updated when
        :meth:`refresh` is called. This token is a JWT. It can be verified
        and decoded using :func:`google.oauth2.id_token.verify_oauth2_token`.
        """
        return self._id_token

    @property
    def client_id(self):
        """Optional[str]: The OAuth 2.0 client ID."""
        return self._client_id

    @property
    def client_secret(self):
        """Optional[str]: The OAuth 2.0 client secret."""
        return self._client_secret

    @property
    def requires_scopes(self):
        """False: OAuth 2.0 credentials have their scopes set when
        the initial token is requested and can not be changed."""
        return False

    @_helpers.copy_docstring(credentials.Credentials)
    def refresh(self, request):
        if (self._refresh_token is None or
                self._token_uri is None or
                self._client_id is None or
                self._client_secret is None):
            raise exceptions.RefreshError(
                'The credentials do not contain the necessary fields need to '
                'refresh the access token. You must specify refresh_token, '
                'token_uri, client_id, and client_secret.')

        access_token, refresh_token, expiry, grant_response = (
            _client.refresh_grant(
                request, self._token_uri, self._refresh_token, self._client_id,
                self._client_secret, self._scopes))

        self.token = access_token
        self.expiry = expiry
        self._refresh_token = refresh_token
        self._id_token = grant_response.get('id_token')

        if self._scopes and 'scopes' in grant_response:
            requested_scopes = frozenset(self._scopes)
            granted_scopes = frozenset(grant_response['scopes'].split())
            scopes_requested_but_not_granted = (
                requested_scopes - granted_scopes)
            if scopes_requested_but_not_granted:
                raise exceptions.RefreshError(
                    'Not all requested scopes were granted by the '
                    'authorization server, missing scopes {}.'.format(
                        ', '.join(scopes_requested_but_not_granted)))

    @classmethod
    def from_authorized_user_info(cls, info, scopes=None):
        """Creates a Credentials instance from parsed authorized user info.
        Args:
            info (Mapping[str, str]): The authorized user info in Google
                format.
            scopes (Sequence[str]): Optional list of scopes to include in the
                credentials.
        Returns:
            google.oauth2.credentials.Credentials: The constructed
                credentials.
        Raises:
            ValueError: If the info is not in the expected format.
        """
        keys_needed = set(('refresh_token', 'client_id', 'client_secret'))
        missing = keys_needed.difference(six.iterkeys(info))

        if missing:
            raise ValueError(
                'Authorized user info was not in the expected format, missing '
                'fields {}.'.format(', '.join(missing)))

        # Scopes shouldn't be needed for authorized credentials, but can be
        # useful to keep for accounting of stored credentials.
        # This lets stored scopes be imported, instead of relying solely on
        # scopes passed as method arguments.
        if scopes is not None:
            _scopes = set(scopes+info.get('scopes'))
        else:
            _scopes = info.get('scopes')

        # TODO: what is the idea behind passing scopes as arguments here and in
        # `from_authorized_user_file` below? Should it go away? Should it be
        # passed in a more consistent way, together with `info`? Why should they
        # be separate from `info`?

        return cls(
            # TODO: ignoring the access token and letting the upper layers
            # handle token refresh works, but is it the right way to do? We
            # could have a valid token that doesn't need refresh in case a
            # script runs every few minutes.
            None,  # No access token, must be refreshed.
            refresh_token=info['refresh_token'],
            token_uri=_GOOGLE_OAUTH2_TOKEN_ENDPOINT,
            scopes=_scopes,
            client_id=info['client_id'],
            client_secret=info['client_secret'])

    @classmethod
    def from_authorized_user_file(cls, filename, scopes=None):
        """Creates a Credentials instance from an authorized user json file.
        Args:
            filename (str): The path to the authorized user json file.
            scopes (Sequence[str]): Optional list of scopes to include in the
                credentials.
        Returns:
            google.oauth2.credentials.Credentials: The constructed
                credentials.
        Raises:
            ValueError: If the file is not in the expected format.
        """
        with io.open(filename, 'r', encoding='utf-8') as json_file:
            data = json.load(json_file)
            return cls.from_authorized_user_info(data, scopes)

    def to_json(self, strip=None, to_serialize=None, indent=2):
        """Utility function that creates JSON repr. of a Credentials object.
        Args:
            strip: array, (Optional) An array of names of members to exclude
                   from the JSON.
            to_serialize: dict, (Optional) The properties for this object
                          that will be serialized. This allows callers to
                          modify before serializing.
        Returns:
            string, a JSON representation of this instance, suitable to pass to
            from_json().

        Adjusted from https://github.com/googleapis/oauth2client.
        """
        # curr_type = self.__class__

        # if to_serialize is not None:
        #     # Assumes it is a str->str dictionary, so we don't deep copy.
        #     to_serialize = copy.copy(to_serialize)
        # else:
        #     # With Google.auth, most Credentials attributes are protected
        #     # Due to the way we retrieve them for serialization then storing,
        #     # we copy the attributes one by one and remove the `_` prefix
        #     # when present.
        #     RM_PREFIX = '_'
        #     to_serialize = {}
        #     for obj_key in self.__dict__:
        #         # Case where we remove the `_`
        #         if obj_key.startswith(RM_PREFIX):
        #             sanitized_key = obj_key.split(RM_PREFIX, maxsplit=1)[-1]
        #             to_serialize[sanitized_key] = self.__dict__[obj_key]
        #         # Other cases:
        #         else:
        #             to_serialize[obj_key] = self.__dict__[obj_key]

        # if strip is not None:
        #     for member in strip:
        #         if member in to_serialize:
        #             del to_serialize[member]

        # # Convert time from `datetime.datetime` object into a string
        # # This lib uses the `expiry` property, therefore checking for
        # # that keyword only.
        # if to_serialize.get('expiry'):
        #     to_serialize['expiry'] = _helpers.parse_expiry(
        #             to_serialize['expiry'])

        # # Add in information we will need later to reconstitute this instance.
        # to_serialize['_class'] = curr_type.__name__
        # to_serialize['_module'] = curr_type.__module__

        # for key, val in to_serialize.items():
        #     if isinstance(val, bytes):
        #         to_serialize[key] = val.decode('utf-8')
        #     if isinstance(val, set):
        #         to_serialize[key] = list(val)

        # return json.dumps(to_serialize, indent=indent)


        # The above was taken and adjusted from oauth2client
        # https://github.com/googleapis/oauth2client/blob/master/oauth2client/client.py
        # It seems unnecessarily complicated.
        # Perhaps this would be a lot simpler and readable?

        # Case where we have a `to_serialize` argument given
        if to_serialize is not None:
            to_serialize = copy.copy(to_serialize)
        # Otherwise, prepare the response
        else:
            to_serialize = {
                    'token':            self.token,
                    'refresh_token':    self.refresh_token,
                    'token_uri':        self.token_uri,
                    'client_id':        self.client_id,
                    'client_secret':    self.client_secret,
                    'scopes':           self.scopes,
                    'expiry':           self.expiry.timestamp()}
            # If a `strip` argument is given, we remove those members from the
            # compiled dict/JSON here
            if strip is not None:
                for member in strip:
                    if member in to_serialize:
                        del to_serialize[member]

        return json.dumps(to_serialize, indent=indent)
