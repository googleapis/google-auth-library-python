# Copyright 2016 Google LLC
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
import datetime
import threading
from enum import Enum
from typing import Optional, Dict, Any, Mapping, MutableMapping, Sequence, cast
import os

import rewired.auth.credentials as external_creds
from rewired.auth import _helpers, environment_vars
from rewired.auth import exceptions
from rewired.auth import metrics
from rewired.auth._credentials_base import _BaseCredentials
from rewired.auth._refresh_worker import RefreshThreadManager
from rewired.auth.transport.requests import Request
from rewired.auth.crypt import Signer

DEFAULT_UNIVERSE_DOMAIN = "googleapis.com"


class TokenState(Enum):
    """The token state returned by `Credentials.token_state`."""

    INVALID = "INVALID"
    STALE = "STALE"
    FRESH = "FRESH"


class Credentials(_BaseCredentials):
    """Base class for all credentials."""

    def __init__(self) -> None:
        super(Credentials, self).__init__()  # type: ignore[no-untyped-call]
        self.expiry: Optional[datetime.datetime] = None
        self._quota_project_id: Optional[str] = None
        self._trust_boundary: Optional[Dict[str, Any]] = None
        self._universe_domain: str = DEFAULT_UNIVERSE_DOMAIN
        self._use_non_blocking_refresh: bool = False
        self._refresh_worker: RefreshThreadManager = RefreshThreadManager()
        self._lock: threading.Lock = threading.Lock()

    @property
    def expired(self) -> bool:
        if not self.expiry:
            return False
        skewed_expiry = self.expiry - _helpers.REFRESH_THRESHOLD
        return _helpers.utcnow() >= skewed_expiry  # type: ignore

    @property
    def valid(self) -> bool:
        return self.token is not None and not self.expired

    @property
    def token_state(self) -> TokenState:
        if self.token is None:
            return TokenState.INVALID
        if self.expiry is None:
            return TokenState.FRESH
        if _helpers.utcnow() >= self.expiry:  # type: ignore
            return TokenState.INVALID
        if _helpers.utcnow() >= (self.expiry - _helpers.REFRESH_THRESHOLD):  # type: ignore
            return TokenState.STALE
        return TokenState.FRESH

    @property
    def quota_project_id(self) -> Optional[str]:
        return self._quota_project_id

    @property
    def universe_domain(self) -> str:
        return self._universe_domain

    def get_cred_info(self) -> Optional[Mapping[str, str]]:
        return None

    @abc.abstractmethod
    def refresh(self, request: Request) -> None:
        raise NotImplementedError("Refresh must be implemented")

    def _metric_header_for_usage(self) -> Optional[str]:
        return None

    def apply(self, headers: MutableMapping[str, str], token: Optional[str] = None) -> None:
        self._apply(headers, token=token)  # type: ignore
        if self._trust_boundary is not None:
            headers["x-allowed-locations"] = self._trust_boundary["encoded_locations"]
        if self.quota_project_id:
            headers["x-goog-user-project"] = self.quota_project_id

    def _blocking_refresh(self, request: Request) -> None:
        with self._lock:
            if not getattr(self, "requires_scopes", False):  # type: ignore[attr-defined]
                self.refresh(request)

    def _non_blocking_refresh(self, request: Request) -> None:
        self._refresh_worker.refresh_on_background_thread(
            cast(external_creds.Credentials, self), request, self._lock
        )

    def before_request(
        self, request: Request, method: str, url: str, headers: MutableMapping[str, str]
    ) -> None:
        if self._use_non_blocking_refresh:
            self._non_blocking_refresh(request)
        else:
            self._blocking_refresh(request)
        self.apply(headers)

    def with_non_blocking_refresh(self, non_blocking: bool = True) -> "Credentials":
        if self._use_non_blocking_refresh == non_blocking:
            return self
        new = self.__class__.__new__(self.__class__)
        new.__dict__.update(self.__dict__)
        new._use_non_blocking_refresh = non_blocking
        return new


class CredentialsWithQuotaProject(Credentials):
    def with_quota_project(self, quota_project_id: str) -> "CredentialsWithQuotaProject":
        raise NotImplementedError("with_quota_project must be implemented.")


class CredentialsWithTokenUri(Credentials):
    def with_token_uri(self, token_uri: str) -> "CredentialsWithTokenUri":
        raise NotImplementedError("with_token_uri must be implemented.")


class AnonymousCredentials(Credentials):
    def __init__(self) -> None:
        super(AnonymousCredentials, self).__init__()
        self.token: Optional[str] = None

    @property
    def expired(self) -> bool:
        return False

    @property
    def valid(self) -> bool:
        return True

    @property
    def token_state(self) -> TokenState:
        return TokenState.FRESH

    def refresh(self, request: Request) -> None:
        return

    def apply(self, headers: MutableMapping[str, str], token: Optional[str] = None) -> None:
        return

    def before_request(
        self, request: Request, method: str, url: str, headers: MutableMapping[str, str]
    ) -> None:
        return


class Scoped:
    @property
    def requires_scopes(self) -> bool:
        raise NotImplementedError("requires_scopes must be implemented.")

    def with_scopes(
        self,
        scopes: Sequence[str],
        default_scopes: Optional[Sequence[str]] = None,
    ) -> "Scoped":
        raise NotImplementedError("with_scopes must be implemented.")


class ReadOnlyScoped(Scoped):
    @property
    def scopes(self) -> Optional[Sequence[str]]:
        raise NotImplementedError("scopes must be implemented.")

    @property
    def default_scopes(self) -> Optional[Sequence[str]]:
        raise NotImplementedError("default_scopes must be implemented.")


class Signing:
    @property
    def signer(self) -> Signer:
        raise NotImplementedError("signer must be implemented.")

    @property
    def signer_email(self) -> str:
        raise NotImplementedError("signer_email must be implemented.")

    def sign_bytes(self, message: bytes) -> bytes:
        raise NotImplementedError("sign_bytes must be implemented.")


class CredentialsWithSigner(Signing):
    def with_signer(self, signer: Signer) -> "CredentialsWithSigner":
        raise NotImplementedError("with_signer must be implemented.")
