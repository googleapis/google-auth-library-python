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


"""Interface for base credentials."""

import abc
from enum import Enum

from google.auth import _helpers
from google.auth import metrics
from google.auth._refresh_worker import RefreshThreadManager

_DEFAULT_UNIVERSE_DOMAIN = "googleapis.com"


class _BaseCredentials(metaclass=abc.ABCMeta):
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
        self._quota_project_id = None
        """Optional[str]: Project to use for quota and billing purposes."""
        self._trust_boundary = None
        """Optional[dict]: Cache of a trust boundary response which has a list
        of allowed regions and an encoded string representation of credentials
        trust boundary."""
        self._universe_domain = _DEFAULT_UNIVERSE_DOMAIN
        """Optional[str]: The universe domain value, default is googleapis.com
        """

        self._use_non_blocking_refresh = False
        # TODO(omairn): RefreshThreadManager() may be specific to sync refresh and may need to be separately implemented for async. If so,
        # move it back to credentials.py
        self._refresh_worker = RefreshThreadManager()

    @property
    # TODO(omairn): We could alternatively not implement this here and use asyncio.get_event_loop().time() for the case of async
    # since utcnow() is a sync function.
    def expired(self):
        """Checks if the credentials are expired.

        Note that credentials can be invalid but not expired because
        Credentials with :attr:`expiry` set to None is considered to never
        expire.

        .. deprecated:: v2.24.0
          Prefer checking :attr:`token_state` instead.
        """
        if not self.expiry:
            return False
        # Remove some threshold from expiry to err on the side of reporting
        # expiration early so that we avoid the 401-refresh-retry loop.
        skewed_expiry = self.expiry - _helpers.REFRESH_THRESHOLD
        return _helpers.utcnow() >= skewed_expiry

    @property
    def valid(self):
        """Checks the validity of the credentials.

        This is True if the credentials have a :attr:`token` and the token
        is not :attr:`expired`.

        .. deprecated:: v2.24.0
          Prefer checking :attr:`token_state` instead.
        """
        return self.token is not None and not self.expired

    @property
    def token_state(self):
        """
        See `:obj:`_TokenState`
        """
        if self.token is None:
            return _TokenState.INVALID

        # Credentials that can't expire are always treated as fresh.
        if self.expiry is None:
            return _TokenState.FRESH

        expired = _helpers.utcnow() >= self.expiry
        if expired:
            return _TokenState.INVALID

        is_stale = _helpers.utcnow() >= (self.expiry - _helpers.REFRESH_THRESHOLD)
        if is_stale:
            return _TokenState.STALE

        return _TokenState.FRESH

    @property
    def quota_project_id(self):
        """Project to use for quota and billing purposes."""
        return self._quota_project_id

    @property
    def universe_domain(self):
        """The universe domain value."""
        return self._universe_domain

    @abc.abstractmethod
    def refresh(self, request):
        """Refreshes the access token.

        Args:
            request (google.auth.transport.Request): The object used to make
                HTTP requests.

        Raises:
            google.auth.exceptions.RefreshError: If the credentials could
                not be refreshed.
        """
        # pylint: disable=missing-raises-doc
        # (pylint doesn't recognize that this is abstract)
        raise NotImplementedError("Refresh must be implemented")

    def _metric_header_for_usage(self):
        """The x-goog-api-client header for token usage metric.

        This header will be added to the API service requests in before_request
        method. For example, "cred-type/sa-jwt" means service account self
        signed jwt access token is used in the API service request
        authorization header. Children credentials classes need to override
        this method to provide the header value, if the token usage metric is
        needed.

        Returns:
            str: The x-goog-api-client header value.
        """
        return None

    def _apply(self, headers, token=None):
        """Apply the token to the authentication header.

        Args:
            headers (Mapping): The HTTP request headers.
            token (Optional[str]): If specified, overrides the current access
                token.
        """
        headers["authorization"] = "Bearer {}".format(
            _helpers.from_bytes(token or self.token)
        )
        """Trust boundary value will be a cached value from global lookup.

        The response of trust boundary will be a list of regions and a hex
        encoded representation.

        An example of global lookup response:
        {
          "locations": [
            "us-central1", "us-east1", "europe-west1", "asia-east1"
          ]
          "encoded_locations": "0xA30"
        }
        """
        if self._trust_boundary is not None:
            headers["x-allowed-locations"] = self._trust_boundary["encoded_locations"]
        if self.quota_project_id:
            headers["x-goog-user-project"] = self.quota_project_id


class _TokenState(Enum):
    """
    Tracks the state of a token.
    FRESH: The token is valid. It is not expired or close to expired, or the token has no expiry.
    STALE: The token is close to expired, and should be refreshed. The token can be used normally.
    INVALID: The token is expired or invalid. The token cannot be used for a normal operation.
    """

    FRESH = 1
    STALE = 2
    INVALID = 3
