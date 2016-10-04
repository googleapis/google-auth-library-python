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


"""Interfaces for credentials."""

import abc

import six

from google.auth import _helpers


@six.add_metaclass(abc.ABCMeta)
class Credentials(object):
    """Base class for all credentials.

    All credentials have a :attr:`token` that is used for authentication and
    may also optionally set an :attr:`expiry` to indicate when the token will
    no longer be valid.

    Most credentials will be :attr:`invalid` until :meth:`refresh` is called.
    Credentials can do this automatically before the first HTTP request in
    :meth:`before_request`.

    Although the token and expiration will change as the credentials are
    :meth:`refreshed <refresh>` and used, credentials should be considered
    immutable. Various credentials will accept configuration such as private
    keys, scopes, and other options. These options are not changeable after
    construction. Some classes will provide mechanisms to copy the credentials
    with modifications such as :meth:`ScopedCredentials.with_scopes`.
    """
    def __init__(self):
        self.token = None
        """str: The bearer token that can be used in HTTP headers to make
        authenticated requests."""
        self.expiry = None
        """Optional[datetime]: When the token expires and is no longer valid.
        If this is None, the token is assumed to never expire."""

    @property
    def valid(self):
        """Checks the validity of the credentials.

        This is True if the credentials have a :attr:`token` and the token
        is not :attr:`expired`.
        """
        return self.token is not None and not self.expired

    @property
    def expired(self):
        """Checks if the credentials are expired.

        Note that credentials can be invalid but not expired becaue Credentials
        with :attr:`expiry` set to None is considered to never expire.
        """
        now = _helpers.now()
        if self.expiry is None or self.expiry > now:
            return False
        else:
            return True

    @abc.abstractmethod
    def refresh(self, request):
        """Refreshes the access token.

        Args:
            request (google.auth.transport.Request): A callable used to make
                HTTP requests.

        Raises:
            google.auth.exceptions.RefreshError: If the credentials could
                not be refreshed.
        """
        # pylint: disable=missing-raises-doc
        # (pylint doesn't recognize that this is abstract)
        raise NotImplementedError('Refresh must be implemented')

    def apply(self, headers, token=None):
        """Apply the token to the authentication header.

        Args:
            headers (Mapping): The HTTP request headers.
            token (Optional[str]): If specified, overrides the current access
                token.
        """
        headers[b'authorization'] = 'Bearer {}'.format(
            _helpers.from_bytes(token or self.token))

    def before_request(self, request, method, url, headers):
        """Performs credential-specific before request logic.

        Refreshes the credentials if necessary, then calls :meth:`apply` to
        apply the token to the authentication header.

        Args:
            request (google.auth.transport.Request): A callable used to make
                HTTP requests.
            method (str): The request's HTTP method.
            url (str): The request's URI.
            headers (Mapping): The request's headers.
        """
        # pylint: disable=unused-argument
        # (Subclasses may use these arguments to ascertain information about
        # the http request.)
        if not self.valid:
            self.refresh(request)
        self.apply(headers)


@six.add_metaclass(abc.ABCMeta)
class ScopedCredentials(object):
    """Interface for scoped credentials.

    OAuth 2.0-based credentials allow limiting access using scopes as described
    in `RFC6749 <https://tools.ietf.org/html/rfc6749#section-3.3>`__.
    If a credential class implements this interface then the credentials either
    require or use scopes in their implementation.

    Credentials that require scopes to obtain access tokens must either be
    constructed with scopes::

        credentials = SomeScopedCredentials(scopes=['one', 'two'])

    Or must copy an existing instance using :meth:`with_scopes`::

        scoped_credentials = credentials.with_scopes(scopes=['one', 'two'])

    Some credentials have scopes but do not allow or require scopes to be set.
    You can check if scoping is necessary with :attr:`requires_scopes`::

        if credentials.requires_scopes:
            credentials = credentials.create_scoped(['one', 'two'])

    """
    def __init__(self):
        super(ScopedCredentials, self).__init__()
        self.__scopes = None

    @property
    def _scopes(self):
        return self.__scopes

    @_scopes.setter
    def _scopes(self, value):
        self.__scopes = _helpers.string_to_scopes(value)

    @abc.abstractproperty
    def requires_scopes(self):
        """True if these credentials require scopes to obtain an access token.
        """
        return False

    @abc.abstractmethod
    def with_scopes(self, scopes):
        """Create a copy of these credentials with the specified scopes.

        Args:
            scopes (Union[str, Sequence]): The scope or list of scopes to
                request.

        Raises:
            NotImplementedError: If the credentials' scopes can not be changed.
                This can be avoided by checking :attr:`requires_scopes` before
                calling this method.
        """
        raise NotImplementedError('This class does not require scoping.')

    def has_scopes(self, scopes):
        """Checks if the credentials have the given scopes.

        .. warning: This method is not guarenteed to be accurate if the
            credentials are :attr:`~Credentials.invalid`.

        Returns:
            bool: True if the credentials have the given scopes.
        """
        return set(scopes).issubset(set(self._scopes or []))


@six.add_metaclass(abc.ABCMeta)
class SigningCredentials(object):
    """Interface for credentials that can cryptographically sign messages."""

    @abc.abstractmethod
    def sign_bytes(self, message):
        """Signs the given message.

        Args:
            message (bytes): The message to sign.

        Returns:
            bytes: The messages cryptographic signature.
        """
        # pylint: disable=missing-raises-doc,redundant-returns-doc
        # (pylint doesn't recognize that this is abstract)
        raise NotImplementedError('Sign bytes must be implemented.')
