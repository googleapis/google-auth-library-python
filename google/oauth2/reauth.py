# Copyright 2021 Google LLC
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

"""A module that provides functions for handling rapt authentication.

Reauth is a process of obtaining additional authentication (such as password,
security token, etc.) while refreshing OAuth 2.0 credentials for a user.

Credentials that use the Reauth flow must have the reauth scope,
``https://www.googleapis.com/auth/accounts.reauth``.

This module provides a high-level function for executing the Reauth process,
:func:`refresh_grant`, and lower-level helpers for doing the individual
steps of the reauth process.

Those steps are:

1. Obtaining a list of challenges from the reauth server.
2. Running through each challenge and sending the result back to the reauth
   server.
3. Refreshing the access token using the returned rapt token.
"""

import sys

from six.moves import range

from google.auth import exceptions
from google.oauth2 import _client
from google.oauth2 import challenges


_REAUTH_SCOPE = "https://www.googleapis.com/auth/accounts.reauth"
_REAUTH_API = "https://reauth.googleapis.com/v2/sessions"

_REAUTH_NEEDED_ERROR = "invalid_grant"
_REAUTH_NEEDED_ERROR_INVALID_RAPT = "invalid_rapt"
_REAUTH_NEEDED_ERROR_RAPT_REQUIRED = "rapt_required"

_AUTHENTICATED = "AUTHENTICATED"
_CHALLENGE_REQUIRED = "CHALLENGE_REQUIRED"
_CHALLENGE_PENDING = "CHALLENGE_PENDING"


def _get_challenges(
    request, supported_challenge_types, access_token, requested_scopes=None
):
    """Does initial request to reauth API to get the challenges.

    Args:
        request (google.auth.transport.Request): A callable used to make
            HTTP requests.
        supported_challenge_types (Sequence[str]): list of challenge names
            supported by the manager.
        access_token (str): Access token with reauth scopes.
        requested_scopes (list[str]): Authorized scopes for the credentials.

    Returns:
        dict: The response from the reauth API.
    """
    body = {"supportedChallengeTypes": supported_challenge_types}
    if requested_scopes:
        body["oauthScopesForDomainPolicyLookup"] = requested_scopes

    return _client._token_endpoint_request(
        request, _REAUTH_API + ":start", body, access_token=access_token, use_json=True
    )


def _send_challenge_result(
    request, session_id, challenge_id, client_input, access_token
):
    """Attempt to refresh access token by sending next challenge result.

    Args:
        request (google.auth.transport.Request): A callable used to make
            HTTP requests.
        session_id (str): session id returned by the initial reauth call.
        challenge_id (str): challenge id returned by the initial reauth call.
        client_input: dict with a challenge-specific client input. For example:
            ``{'credential': password}`` for password challenge.
        access_token (str): Access token with reauth scopes.

    Returns:
        dict: The response from the reauth API.
    """
    body = {
        "sessionId": session_id,
        "challengeId": challenge_id,
        "action": "RESPOND",
        "proposalResponse": client_input,
    }

    return _client._token_endpoint_request(
        request,
        _REAUTH_API + "/{}:continue".format(session_id),
        body,
        access_token=access_token,
        use_json=True,
    )


def _run_next_challenge(msg, request, access_token):
    """Get the next challenge from msg and run it.

    Args:
        msg: Reauth API response body (either from the initial request to
            https://reauth.googleapis.com/v2/sessions:start or from sending the
            previous challenge response to
            https://reauth.googleapis.com/v2/sessions/id:continue)
        request (google.auth.transport.Request): A callable used to make
            HTTP requests.
        access_token: reauth access token

    Returns:
        dict: The response from the reauth API.

    Raises:
        google.auth.exceptions.ReauthError: if reauth failed.
    """
    for challenge in msg["challenges"]:
        if challenge["status"] != "READY":
            # Skip non-activated challneges.
            continue
        c = challenges.AVAILABLE_CHALLENGES.get(challenge["challengeType"], None)
        if not c:
            raise exceptions.ReauthFailError(
                "Unsupported challenge type {0}. Supported types: {1}".format(
                    challenge["challengeType"],
                    ",".join(list(challenges.AVAILABLE_CHALLENGES.keys())),
                )
            )
        if not c.is_locally_eligible:
            raise exceptions.ReauthFailError(
                "Challenge {0} is not locally eligible".format(
                    challenge["challengeType"]
                )
            )
        client_input = c.obtain_challenge_input(challenge)
        if not client_input:
            return None
        return _send_challenge_result(
            request,
            msg["sessionId"],
            challenge["challengeId"],
            client_input,
            access_token,
        )
    return None


def _obtain_rapt(request, access_token, requested_scopes, rounds_num=5):
    """Given an http request method and reauth access token, get rapt token.

    Args:
        request (google.auth.transport.Request): A callable used to make
            HTTP requests.
        access_token: reauth access token
        requested_scopes: scopes required by the client application
        rounds_num: max number of attempts to get a rapt after the next
            challenge, before failing the reauth. This defines total number of
            challenges + number of additional retries if the chalenge input
            wasn't accepted.

    Returns:
        str: The rapt token.

    Raises:
        google.auth.exceptions.ReauthError: if reauth failed
    """
    msg = None

    for _ in range(0, rounds_num):

        if not msg:
            msg = _get_challenges(
                request,
                list(challenges.AVAILABLE_CHALLENGES.keys()),
                access_token,
                requested_scopes,
            )

        if msg["status"] == _AUTHENTICATED:
            return msg["encodedProofOfReauthToken"]

        if not (
            msg["status"] == _CHALLENGE_REQUIRED or msg["status"] == _CHALLENGE_PENDING
        ):
            raise exceptions.ReauthFailError(
                "Reauthentication challenge failed due to API error: {}".format(
                    msg["status"]
                )
            )

        """Check if we are in an interractive environment.

        If the rapt token needs refreshing, the user needs to answer the
        challenges.
        """
        if not sys.stdin.isatty():
            raise exceptions.ReauthFailError(
                "Reauthentication challenge could not be answered because you are not in an interactive session."
            )

        msg = _run_next_challenge(msg, request, access_token)

    # If we got here it means we didn't get authenticated.
    raise exceptions.ReauthFailError()


def get_rapt_token(
    request, client_id, client_secret, refresh_token, token_uri, scopes=None
):
    """Given an http request method and refresh_token, get rapt token.

    Args:
        request (google.auth.transport.Request): A callable used to make
            HTTP requests.
        client_id: client id to get access token for reauth scope.
        client_secret: client secret for the client_id
        refresh_token: refresh token to refresh access token
        token_uri: uri to refresh access token
        scopes: scopes required by the client application

    Returns: rapt token.
    Raises:
        google.auth.exceptions.ReauthError if reauth failed
    """
    sys.stderr.write("Reauthentication required.\n")

    try:
        # Get access token for reauth.
        access_token, _, _, _ = _client.refresh_grant(
            request=request,
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token,
            token_uri=token_uri,
            scopes=[_REAUTH_SCOPE],
        )

        # Get rapt token from reauth API.
        rapt_token = _obtain_rapt(request, access_token, requested_scopes=scopes)

        return rapt_token
    except exceptions.RefreshError as e:
        # TODO: convert refresh error to reauth error?
        raise e


def refresh_grant(
    request,
    token_uri,
    refresh_token,
    client_id,
    client_secret,
    scopes=None,
    rapt_token=None,
):
    """Implements the OAuth 2.0 refresh token grant.

    For more details, see `rfc678 section 6`_.

    Args:
        request (google.auth.transport.Request): A callable used to make
            HTTP requests.
        token_uri (str): The OAuth 2.0 authorizations server's token endpoint
            URI.
        refresh_token (str): The refresh token to use to get a new access
            token.
        client_id (str): The OAuth 2.0 application's client ID.
        client_secret (str): The Oauth 2.0 appliaction's client secret.
        scopes (Optional(Sequence[str])): Scopes to request. If present, all
            scopes must be authorized for the refresh token. Useful if refresh
            token has a wild card scope (e.g.
            'https://www.googleapis.com/auth/any-api').

    Returns:
        Tuple[str, Optional[str], Optional[datetime], Mapping[str, str]]: The
            access token, new refresh token, expiration, and additional data
            returned by the token endpoint.

    Raises:
        google.auth.exceptions.RefreshError: If the token endpoint returned
            an error.

    .. _rfc6748 section 6: https://tools.ietf.org/html/rfc6749#section-6
    """
    body = {
        "grant_type": _client._REFRESH_GRANT_TYPE,
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
    }
    if scopes:
        body["scope"] = " ".join(scopes)
    if rapt_token:
        body["rapt"] = rapt_token

    try:
        response_status_ok, response_data = _client._token_endpoint_request_no_throw(
            request, token_uri, body
        )
        if (
            not response_status_ok
            and response_data.get("error") == _REAUTH_NEEDED_ERROR
            and (
                response_data.get("error_subtype") == _REAUTH_NEEDED_ERROR_INVALID_RAPT
                or response_data.get("error_subtype")
                == _REAUTH_NEEDED_ERROR_RAPT_REQUIRED
            )
        ):
            rapt_token = get_rapt_token(
                request,
                client_id,
                client_secret,
                refresh_token,
                token_uri,
                scopes=scopes,
            )
            body["rapt"] = rapt_token
            (
                response_status_ok,
                response_data,
            ) = _client._token_endpoint_request_no_throw(request, token_uri, body)

        if not response_status_ok:
            _client._handle_error_response(response_data)
        return _client._handle_refresh_grant_response(response_data, refresh_token) + (
            rapt_token,
        )
    except exceptions.RefreshError as e:
        # TODO: convert to reauth error
        raise e
