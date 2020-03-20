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

"""Unit tests for google3.third_party.py.google.oauth2.aio._client.

Tests asynchronous oauth2 flow written with pytest to use the async plugin.
"""

import datetime
import http
import json
from typing import Any, Mapping, Text

import mock
import pytest

from google.auth import _helpers
from google.auth import exceptions
from google.auth import transport
from google.oauth2.aio import _client

SCOPES_AS_LIST = [
    "https://www.googleapis.com/auth/pubsub",
    "https://www.googleapis.com/auth/logging.write",
]
SCOPES_AS_STRING = (
    "https://www.googleapis.com/auth/pubsub"
    " https://www.googleapis.com/auth/logging.write"
)


def make_request(
    response_data: Mapping[Text, Text], status: http.HTTPStatus = http.HTTPStatus.OK
):
    """Request is now an awaitable."""
    response = mock.create_autospec(transport.Response, instance=True)
    response.status = status
    response.data = json.dumps(response_data).encode("utf-8")

    async def mock_response(
        url: Text,
        method: Text = "get",
        body: Any = None,
        headers: Mapping[Text, Text] = None,
        **kwargs
    ):
        del url, method, body, headers, kwargs
        return response

    return mock_response


@pytest.mark.asyncio
async def test__token_endpoint_request():
    request = make_request({"test": "response"})

    result = await _client._token_endpoint_request(
        request, "http://example.com", {"test": "params"}
    )

    # Check result
    assert result == {"test": "response"}


@pytest.mark.asyncio
async def test__token_endpoint_request_error():
    request = make_request({}, status=http.HTTPStatus.BAD_REQUEST)

    with pytest.raises(exceptions.RefreshError):
        await _client._token_endpoint_request(request, "http://example.com", {})


@pytest.mark.asyncio
async def test__token_endpoint_request_internal_failure_error():
    request = make_request(
        {"error_description": "internal_failure"}, status=http.HTTPStatus.BAD_REQUEST
    )

    with pytest.raises(exceptions.RefreshError):
        await _client._token_endpoint_request(
            request, "http://example.com", {"error_description": "internal_failure"}
        )

    request = make_request(
        {"error": "internal_failure"}, status=http.HTTPStatus.BAD_REQUEST
    )

    with pytest.raises(exceptions.RefreshError):
        await _client._token_endpoint_request(
            request, "http://example.com", {"error": "internal_failure"}
        )


@pytest.mark.asyncio
async def test_jwt_grant():
    request = make_request(
        {"access_token": "token", "expires_in": 500, "extra": "data"}
    )
    with mock.patch(
        "google.auth._helpers.utcnow", return_value=datetime.datetime.min
    ) as utcnow:
        token, expiry, extra_data = await _client.jwt_grant(
            request, "http://example.com", "assertion_value"
        )

        # Check result
        assert token == "token"
        assert expiry == utcnow() + datetime.timedelta(seconds=500)
        assert extra_data["extra"] == "data"


@pytest.mark.asyncio
async def test_jwt_grant_no_access_token():
    request = make_request(
        {
            # No access token.
            "expires_in": 500,
            "extra": "data",
        }
    )

    with pytest.raises(exceptions.RefreshError):
        await _client.jwt_grant(request, "http://example.com", "assertion_value")


@pytest.mark.asyncio
async def test_id_token_jwt_grant():
    now = _helpers.utcnow()
    id_token_expiry = _helpers.datetime_to_secs(now)
    id_token = "a_real_token"
    request = make_request({"id_token": "a_real_token", "extra": "data"})

    mock_payload = {"exp": id_token_expiry}
    with mock.patch("google.auth.jwt.decode", return_value=mock_payload):
        token, expiry, extra_data = await _client.id_token_jwt_grant(
            request, "http://example.com", "assertion_value"
        )

        # Check result
        assert token == id_token
        # JWT does not store microseconds
        now = now.replace(microsecond=0)
        assert expiry == now
        assert extra_data["extra"] == "data"


@pytest.mark.asyncio
async def test_id_token_jwt_grant_no_access_token():
    request = make_request(
        {
            # No access token.
            "expires_in": 500,
            "extra": "data",
        }
    )

    with pytest.raises(exceptions.RefreshError):
        await _client.id_token_jwt_grant(
            request, "http://example.com", "assertion_value"
        )


@pytest.mark.asyncio
async def test_refresh_grant():
    request = make_request(
        {
            "access_token": "token",
            "refresh_token": "new_refresh_token",
            "expires_in": 500,
            "extra": "data",
        }
    )

    with mock.patch("google.auth._helpers.utcnow", return_value=datetime.datetime.min):
        token, refresh_token, expiry, extra_data = await _client.refresh_grant(
            request, "http://example.com", "refresh_token", "client_id", "client_secret"
        )

        # Check result
        assert token == "token"
        assert refresh_token == "new_refresh_token"
        assert expiry == datetime.datetime.min + datetime.timedelta(seconds=500)
        assert extra_data["extra"] == "data"


@pytest.mark.asyncio
async def test_refresh_grant_with_scopes():
    request = make_request(
        {
            "access_token": "token",
            "refresh_token": "new_refresh_token",
            "expires_in": 500,
            "extra": "data",
            "scope": SCOPES_AS_STRING,
        }
    )
    with mock.patch("google.auth._helpers.utcnow", return_value=datetime.datetime.min):
        token, refresh_token, expiry, extra_data = await _client.refresh_grant(
            request,
            "http://example.com",
            "refresh_token",
            "client_id",
            "client_secret",
            SCOPES_AS_LIST,
        )

    # Check result.
    assert token == "token"
    assert refresh_token == "new_refresh_token"
    assert expiry == datetime.datetime.min + datetime.timedelta(seconds=500)
    assert extra_data["extra"] == "data"


@pytest.mark.asyncio
async def test_refresh_grant_no_access_token():
    request = make_request(
        {
            # No access token.
            "refresh_token": "new_refresh_token",
            "expires_in": 500,
            "extra": "data",
        }
    )

    with pytest.raises(exceptions.RefreshError):
        await _client.refresh_grant(
            request, "http://example.com", "refresh_token", "client_id", "client_secret"
        )
