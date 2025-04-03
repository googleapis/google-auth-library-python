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

"""Exceptions used in the google.auth package."""

from typing import Any, Optional


class GoogleAuthError(Exception):
    """Base class for all google.auth errors."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args)
        self._retryable: bool = kwargs.get("retryable", False)

    @property
    def retryable(self) -> bool:
        return self._retryable


class TransportError(GoogleAuthError):
    """Used to indicate an error occurred during an HTTP request."""


class RefreshError(GoogleAuthError):
    """Used to indicate that refreshing the credentials' access token failed."""


class UserAccessTokenError(GoogleAuthError):
    """Used to indicate ``gcloud auth print-access-token`` command failed."""


class DefaultCredentialsError(GoogleAuthError):
    """Used to indicate that acquiring default credentials failed."""


class MutualTLSChannelError(GoogleAuthError):
    """Used to indicate that mutual TLS channel creation failed, or mutual
    TLS channel credentials are missing or invalid."""

    @property
    def retryable(self) -> bool:
        return False


class ClientCertError(GoogleAuthError):
    """Used to indicate that client certificate is missing or invalid."""

    @property
    def retryable(self) -> bool:
        return False


class OAuthError(GoogleAuthError):
    """Used to indicate an error occurred during an OAuth-related HTTP request."""


class ReauthFailError(RefreshError):
    """An exception for when reauth failed."""

    def __init__(self, message: Optional[str] = None, **kwargs: Any) -> None:
        full_message = f"Reauthentication failed. {message}" if message else "Reauthentication failed."
        super().__init__(full_message, **kwargs)


class ReauthSamlChallengeFailError(ReauthFailError):
    """An exception for SAML reauth challenge failures."""


class MalformedError(DefaultCredentialsError, ValueError):
    """An exception for malformed data."""

    def __init__(self, message: Optional[str] = None, **kwargs: Any) -> None:
        super().__init__(message or "Malformed input.", **kwargs)


class InvalidResource(DefaultCredentialsError, ValueError):
    """An exception for URL error."""


class InvalidOperation(DefaultCredentialsError, ValueError):
    """An exception for invalid operation."""


class InvalidValue(DefaultCredentialsError, ValueError):
    """Used to wrap general ValueError of python."""


class InvalidType(DefaultCredentialsError, TypeError):
    """Used to wrap general TypeError of python."""


class OSError(DefaultCredentialsError, EnvironmentError):
    """Used to wrap EnvironmentError (OSError after Python 3.3)."""


class TimeoutError(GoogleAuthError):
    """Used to indicate a timeout error occurred during an HTTP request."""


class ResponseError(GoogleAuthError):
    """Used to indicate an error occurred when reading an HTTP response."""
