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

"""Tests for google.oauth2.aio.credentials."""

import datetime

import mock
import pytest

from google.auth import _helpers
from google.auth import exceptions
from google.auth.transport import aio as aio_transport
from google.oauth2.aio import credentials

ACCESS_TOKEN = "access_token"
TOKEN_URI = "https://example.com/oauth2/token"
REFRESH_TOKEN = "refresh_token"
CLIENT_ID = "client_id"
CLIENT_SECRET = "client_secret"


def make_credentials():
    return credentials.Credentials(
        token=None,
        refresh_token=REFRESH_TOKEN,
        token_uri=TOKEN_URI,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )


@pytest.mark.asyncio
async def test_refresh_success():
    with mock.patch(
        "google.auth._helpers.utcnow",
        return_value=datetime.datetime.min + _helpers.CLOCK_SKEW,
    ) as utcnow:
        token = "token"
        expiry = utcnow() + datetime.timedelta(seconds=500)
        grant_response = {"id_token": mock.sentinel.id_token}

        async def mock_refresh_grant(*args, **kwargs):
            del args
            del kwargs
            return token, None, expiry, grant_response

        with mock.patch(
            "google.oauth2.aio._client.refresh_grant", wraps=mock_refresh_grant
        ) as refresh_grant:
            request = mock.create_autospec(aio_transport.Request)
            creds = make_credentials()

            # Refresh credentials
            await creds.refresh(request)

        # Check jwt grant call.
        refresh_grant.assert_called_with(
            request, TOKEN_URI, REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET
        )

        # Check that the credentials have the token and expiry
        assert creds.token == token
        assert creds.expiry == expiry
        assert creds.id_token == mock.sentinel.id_token

        # Check that the credentials are valid (have a token and are not
        # expired)
        assert creds.valid


@pytest.mark.asyncio
async def test_refresh_no_refresh_token():
    request = mock.create_autospec(aio_transport.Request)
    creds = credentials.Credentials(token=None, refresh_token=None)

    with pytest.raises(exceptions.RefreshError, match="necessary fields"):
        await creds.refresh(request)

    request.assert_not_called()
