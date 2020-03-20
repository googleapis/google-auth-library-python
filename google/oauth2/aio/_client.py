# Lint as: python3
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

"""Async OAuth 2.0 client.

This is a client for interacting with an OAuth 2.0 authorization server's
token endpoint.

For more information about the token endpoint, see
`Section 3.1 of rfc6749`_

.. _Section 3.1 of rfc6749: https://tools.ietf.org/html/rfc6749#section-3.2
"""
import datetime
import http.client
import json
from typing import Mapping, Optional, Sequence, Text, Tuple, Union
import urllib

from google.auth import exceptions
from google.auth import jwt
import google.auth.transport.aio
from google.oauth2 import _client

# pylint: disable=protected-access
_JWT_GRANT_TYPE = _client._JWT_GRANT_TYPE
_REFRESH_GRANT_TYPE = _client._REFRESH_GRANT_TYPE
_URLENCODED_CONTENT_TYPE = _client._URLENCODED_CONTENT_TYPE
_handle_error_response = _client._handle_error_response
_parse_expiry = _client._parse_expiry
# pylint: disable=protected-access


async def _token_endpoint_request(
    request: google.auth.transport.aio.Request,
    token_uri: Text,
    body: Mapping[Text, Text],
    retries: int = 2,
) -> Mapping[Text, Text]:
    """Makes a request to the OAuth 2.0 authorization server's token endpoint.

    Args:
      request: A coroutine used to make HTTP requests.
      token_uri: The OAuth 2.0 authorizations server's token endpoint URI.
      body: The parameters to send in the request body.
      retries: Number of retries allotted if internal failure occurs on request.

    Returns:
      The JSON-decoded response data.

    Raises:
      google.auth.exceptions.RefreshError: If the token endpoint returned
      an error.
    """
    body = urllib.parse.urlencode(body)

    headers = {"content-type": _URLENCODED_CONTENT_TYPE}

    # retry to fetch token if any internal failure occurs.
    for _ in range(1 + retries):
        response = await request(
            method="POST", url=token_uri, headers=headers, body=body
        )
        response_body = (
            response.data.decode("utf-8")
            if hasattr(response.data, "decode")
            else response.data
        )
        response_data = json.loads(response_body)

        if response.status == http.client.OK:
            break
        else:
            error_desc = response_data.get("error_description") or ""
            error_code = response_data.get("error") or ""
            if "internal_failure" not in (error_code, error_desc):
                _handle_error_response(response_body)
    else:
        _handle_error_response(response_body)

    return response_data


async def jwt_grant(
    request: google.auth.transport.aio.Request,
    token_uri: Text,
    assertion: Union[bytes, Text],
) -> Tuple[Text, Optional[datetime.datetime], Mapping[Text, Text]]:
    """Implements the JWT Profile for OAuth 2.0 Authorization Grants.

    For more details, see `rfc7523 section 4`_.

    Args:
      request: A coroutine used to make HTTP requests.
      token_uri: The OAuth 2.0 authorizations server's token endpoint URI.
      assertion: The OAuth 2.0 assertion.

    Returns:
      The access token, expiration, and additional data returned by the token
      endpoint.

    Raises:
      google.auth.exceptions.RefreshError: If the token endpoint returned an
      error.

    .. _rfc7523 section 4: https://tools.ietf.org/html/rfc7523#section-4
    """
    body = {"assertion": assertion, "grant_type": _JWT_GRANT_TYPE}

    response_data = await _token_endpoint_request(request, token_uri, body)

    try:
        access_token = response_data["access_token"]
    except KeyError as caught_exc:
        new_exc = exceptions.RefreshError("No access token in response.", response_data)
        raise new_exc from caught_exc

    expiry = _parse_expiry(response_data)

    return access_token, expiry, response_data


async def id_token_jwt_grant(
    request: google.auth.transport.aio.Request, token_uri: Text, assertion: Text
) -> Tuple[Text, Optional[datetime.datetime], Mapping[Text, Text]]:
    """Implements JWT Profile for OAuth 2.0 with OpenID Connect Token.

    This is a variant on the standard JWT Profile that is currently unique
    to Google. This was added for the benefit of authenticating to services
    that require ID Tokens instead of access tokens or JWT bearer tokens.

    Args:
      request: A coroutine used to make HTTP requests.
      token_uri: The OAuth 2.0 authorization server's token endpoint URI.
      assertion: JWT token signed by a service account. The token's payload must
        include a ``target_audience`` claim.

    Returns:
      The (encoded) Open ID Connect ID Token, expiration, and additional
      data returned by the endpoint.

    Raises:
      google.auth.exceptions.RefreshError: If the token endpoint returned an
      error.
    """
    # pylint: disable=protected-access
    body = {"assertion": assertion, "grant_type": _client._JWT_GRANT_TYPE}

    response_data = await _token_endpoint_request(request, token_uri, body)

    try:
        id_token = response_data["id_token"]
    except KeyError as caught_exc:
        new_exc = exceptions.RefreshError("No ID token in response.", response_data)
        raise new_exc from caught_exc

    payload = jwt.decode(id_token, verify=False)
    expiry = datetime.datetime.utcfromtimestamp(payload["exp"])

    return id_token, expiry, response_data


async def refresh_grant(
    request: google.auth.transport.aio.Request,
    token_uri: Text,
    refresh_token: Text,
    client_id: Text,
    client_secret: Text,
    scopes: Optional[Sequence[Text]] = None,
) -> Tuple[Text, Optional[Text], Optional[datetime.datetime], Mapping[Text, Text]]:
    """Implements the OAuth 2.0 refresh token grant.

    For more details, see `rfc678 section 6`_.

    Args:
      request: A callable used to make HTTP requests.
      token_uri: The OAuth 2.0 authorizations server's token endpoint URI.
      refresh_token: The refresh token to use to get a new access token.
      client_id: The OAuth 2.0 application's client ID.
      client_secret: The Oauth 2.0 appliaction's client secret.
      scopes: Scopes to request. If present, all scopes must be authorized for the
        refresh token. Useful if refresh token has a wild card scope
      (e.g. 'https://www.googleapis.com/auth/any-api').

    Returns:
      The access token, new refresh token, expiration, and additional data
      returned by the token endpoint.

    Raises:
      google.auth.exceptions.RefreshError: If the token endpoint returned
      an error.

    .. _rfc6748 section 6: https://tools.ietf.org/html/rfc6749#section-6
    """
    body = {
        "grant_type": _REFRESH_GRANT_TYPE,
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
    }
    if scopes:
        body["scope"] = " ".join(scopes)

    response_data = await _token_endpoint_request(request, token_uri, body)

    try:
        access_token = response_data["access_token"]
    except KeyError as caught_exc:
        new_exc = exceptions.RefreshError("No access token in response.", response_data)
        raise new_exc from caught_exc

    refresh_token = response_data.get("refresh_token", refresh_token)
    expiry = _client._parse_expiry(response_data)

    return access_token, refresh_token, expiry, response_data
