# Copyright 2020 Google LLC
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

"""OAuth 2.0 Utilities.

Provides OAuth error handling and client authentication utilities.
"""

import abc
import base64
import enum
import json
from typing import Mapping, Optional, MutableMapping, Any

from google.auth import exceptions


class ClientAuthType(enum.Enum):
    basic = 1
    request_body = 2


class ClientAuthentication:
    """OAuth client authentication credentials.

    Args:
        client_auth_type: The client authentication type.
        client_id: The client ID.
        client_secret: The client secret (optional).
    """

    def __init__(
        self,
        client_auth_type: ClientAuthType,
        client_id: str,
        client_secret: Optional[str] = None,
    ) -> None:
        self.client_auth_type = client_auth_type
        self.client_id = client_id
        self.client_secret = client_secret


class OAuthClientAuthHandler(metaclass=abc.ABCMeta):
    """Handles client authentication in OAuth flows."""

    def __init__(self, client_authentication: Optional[ClientAuthentication] = None) -> None:
        self._client_authentication = client_authentication

    def apply_client_authentication_options(
        self,
        headers: MutableMapping[str, str],
        request_body: Optional[MutableMapping[str, str]] = None,
        bearer_token: Optional[str] = None,
    ) -> None:
        """Applies authentication via headers or POST body.

        Args:
            headers: HTTP headers.
            request_body: POST body dictionary (optional).
            bearer_token: Bearer token (optional).
        """
        self._inject_authenticated_headers(headers, bearer_token)
        if bearer_token is None:
            self._inject_authenticated_request_body(request_body)

    def _inject_authenticated_headers(
        self,
        headers: MutableMapping[str, str],
        bearer_token: Optional[str] = None,
    ) -> None:
        if bearer_token is not None:
            headers["Authorization"] = f"Bearer {bearer_token}"
        elif (
            self._client_authentication is not None
            and self._client_authentication.client_auth_type == ClientAuthType.basic
        ):
            username = self._client_authentication.client_id
            password = self._client_authentication.client_secret or ""
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"

    def _inject_authenticated_request_body(
        self,
        request_body: Optional[MutableMapping[str, str]],
    ) -> None:
        if (
            self._client_authentication is not None
            and self._client_authentication.client_auth_type == ClientAuthType.request_body
        ):
            if request_body is None:
                raise exceptions.OAuthError("HTTP request does not support request-body")

            request_body["client_id"] = self._client_authentication.client_id
            request_body["client_secret"] = self._client_authentication.client_secret or ""


def handle_error_response(response_body: str) -> None:
    """Converts OAuth error JSON response to an exception.

    Args:
        response_body: The decoded response data as string.

    Raises:
        OAuthError: A typed exception with error details.
    """
    try:
        error_data: dict[str, Any] = json.loads(response_body)
        error_components = [f"Error code {error_data['error']}"]
        if "error_description" in error_data:
            error_components.append(f": {error_data['error_description']}")
        if "error_uri" in error_data:
            error_components.append(f" - {error_data['error_uri']}")
        error_details = "".join(error_components)
    except (KeyError, ValueError):
        error_details = response_body

    raise exceptions.OAuthError(error_details, response_body)
