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

This module provides implementations for various OAuth 2.0 utilities.
This includes `OAuth error handling`_ and
`Client authentication for OAuth flows`_.

OAuth error handling
--------------------
This will define interfaces for handling OAuth related error responses as
stated in `RFC 6749 section 5.2`_.
This will include a common function to convert these HTTP error responses to a
:class:`google.auth.exceptions.OAuthError` exception.


Client authentication for OAuth flows
-------------------------------------
We introduce an interface for defining client authentication credentials based
on `RFC 6749 section 2.3.1`_. This will expose the following
capabilities:

    * Ability to support basic authentication via request header.
    * Ability to support bearer token authentication via request header.
    * Ability to support client ID / secret authentication via request body.

.. _RFC 6749 section 2.3.1: https://tools.ietf.org/html/rfc6749#section-2.3.1
.. _RFC 6749 section 5.2: https://tools.ietf.org/html/rfc6749#section-5.2
"""

import abc
import base64
import enum
import json

import six

from google.auth import exceptions

_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
_URLENCODED_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


# OAuth client authentication based on
# https://tools.ietf.org/html/rfc6749#section-2.3.
class ClientAuthType(enum.Enum):
    basic = 1
    request_body = 2


class ClientAuthentication(object):
    """Defines the client authentication credentials for basic and request-body
    types based on https://tools.ietf.org/html/rfc6749#section-2.3.1.
    """

    def __init__(self, client_auth_type, client_id, client_secret=None):
        """Instantiates a client authentication object containing the client ID
        and secret credentials for basic and response-body auth.

        Args:
            client_auth_type (google.oauth2.oauth_utils.ClientAuthType): The
                client authentication type.
            client_id (str): The client ID.
            client_secret (Optional[str]): The client secret.
        """
        self.client_auth_type = client_auth_type
        self.client_id = client_id
        self.client_secret = client_secret


@six.add_metaclass(abc.ABCMeta)
class OAuthClientAuthHandler(object):
    """Abstract class for handling client authentication in OAuth-based
    operations.
    """

    def __init__(self, client_authentication=None):
        """Instantiates an OAuth client authentication handler.

        Args:
            client_authentication (Optional[google.oauth2.utils.ClientAuthentication]):
                The OAuth client authentication credentials if available.
        """
        super(OAuthClientAuthHandler, self).__init__()
        self._client_authentication = client_authentication

    def apply_client_authentication_options(
        self, headers, request_body=None, bearer_token=None
    ):
        """Applies client authentication on the OAuth request's headers or POST
        body.

        Args:
            headers (Mapping[str, str]): The HTTP request header.
            request_body (Optional[Mapping[str, str]]): The HTTP request body
                dictionary. For requests that do not support request body, this
                is None and will be ignored.
            bearer_token (Optional[str]): The optional bearer token.
        """
        # Inject authenticated header.
        self._inject_authenticated_headers(headers, bearer_token)
        # Inject authenticated request body.
        if bearer_token is None:
            self._inject_authenticated_request_body(request_body)

    def _inject_authenticated_headers(self, headers, bearer_token=None):
        if bearer_token is not None:
            headers["Authorization"] = "Bearer %s" % bearer_token
        elif (
            self._client_authentication is not None
            and self._client_authentication.client_auth_type is ClientAuthType.basic
        ):
            username = self._client_authentication.client_id
            password = self._client_authentication.client_secret or ""

            credentials = base64.b64encode(
                ("%s:%s" % (username, password)).encode()
            ).decode()
            headers["Authorization"] = "Basic %s" % credentials

    def _inject_authenticated_request_body(self, request_body):
        if (
            self._client_authentication is not None
            and self._client_authentication.client_auth_type
            is ClientAuthType.request_body
        ):
            if request_body is None:
                raise exceptions.OAuthError(
                    "HTTP request does not support request-body"
                )
            else:
                request_body["client_id"] = self._client_authentication.client_id
                request_body["client_secret"] = (
                    self._client_authentication.client_secret or ""
                )


def handle_error_response(response_body):
    """Translates an error response from an OAuth operation into an
    OAuthError exception.

    Args:
        response_body (str): The decoded response data.

    Raises:
        google.auth.exceptions.OAuthError
    """
    try:
        error_components = []
        error_data = json.loads(response_body)

        error_components.append("Error code {}".format(error_data["error"]))
        if "error_description" in error_data:
            error_components.append(": {}".format(error_data["error_description"]))
        if "error_uri" in error_data:
            error_components.append(" - {}".format(error_data["error_uri"]))
        error_details = "".join(error_components)
    # If no details could be extracted, use the response data.
    except (KeyError, ValueError):
        error_details = response_body

    raise exceptions.OAuthError(error_details, response_body)


class TokenIntrospectionClient(OAuthClientAuthHandler):
    """Implements the OAuth 2.0 token introspection spec.

    This is based on https://tools.ietf.org/html/rfc7662.
    The implementation supports 3 types of client authentication when calling
    the endpoints: no authentication, basic header authentication and POST body
    authentication.
    """

    def __init__(self, token_introspect_endpoint, client_authentication=None):
        """Initializes an OAuth introspection client instance.

        Args:
            token_introspect_endpoint (str): The token introspection endpoint.
            client_authentication (Optional[oauth2_utils.ClientAuthentication]):
                The optional OAuth client authentication credentials if available.
        """
        super(TokenIntrospectionClient, self).__init__(client_authentication)
        self._token_introspect_endpoint = token_introspect_endpoint

    def introspect(self, request, token, token_type_hint=_ACCESS_TOKEN_TYPE):
        """Returns the meta-information associated with an OAuth token.

        Args:
            request (google.auth.transport.Request):
                A callable that makes HTTP requests.
            token (str):
                The OAuth token whose meta-information is to be returned.
            token_type_hint (Optional[str]):
                The optional token type. The default is access_token.

        Returns:
          Mapping: The active token meta-information returned by the introspection
            endpoint.

        Raises:
            google.auth.exceptions.UserAccessTokenError:
                If the credentials are invalid or expired.
            google.auth.exceptions.TransportError:
                If an error is encountered while calling the token
                introspection endpoint.
        """
        headers = _URLENCODED_HEADERS.copy()
        request_body = {"token": token, "token_type_hint": token_type_hint}
        # Apply OAuth client authentication.
        self.apply_client_authentication_options(headers, request_body)

        # Execute request.
        response = request(
            url=self._token_introspect_endpoint,
            method="POST",
            headers=headers,
            body=six.moves.urllib.parse.urlencode(request_body).encode("utf-8"),
        )

        response_body = (
            response.data.decode("utf-8")
            if hasattr(response.data, "decode")
            else response.data
        )

        # If non-200 response received, translate to TokenIntrospectionError.
        if response.status != six.moves.http_client.OK:
            raise exceptions.TransportError(response_body)

        response_data = json.loads(response_body)

        if response_data.get("active"):
            return response_data
        else:
            raise exceptions.UserAccessTokenError(response_body)
