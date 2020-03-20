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

"""Tests for google.oauth2.aio.service_account."""

import datetime

import mock
import pytest

from google.auth import _helpers
from google.auth.transport import aio as aio_transport
from google.oauth2.aio import service_account

SIGNER = None
SERVICE_ACCOUNT_EMAIL = "service-account@example.com"
TOKEN_URI = "https://example.com/oauth2/token"


@pytest.fixture
def credentials():
    return service_account.Credentials(SIGNER, SERVICE_ACCOUNT_EMAIL, TOKEN_URI)


@pytest.mark.asyncio
# pylint: disable=redefined-outer-name
async def test_refresh_success(credentials):
    token = "token"

    async def mock_jwt_grant(request, token_uri, assertion):
        return token, _helpers.utcnow() + datetime.timedelta(seconds=500), {}

    with mock.patch(
        "google.oauth2.aio._client.jwt_grant", wraps=mock_jwt_grant
    ) as jwt_grant:
        with mock.patch.object(
            credentials,
            "_make_authorization_grant_assertion",
            return_value="totally_valid_assertion",
        ):
            request = mock.create_autospec(aio_transport.Request, instance=True)

            # Refresh credentials
            await credentials.refresh(request)

            # Check jwt grant call.
            assert jwt_grant.called

        called_request, token_uri, _ = jwt_grant.call_args[0]
        assert called_request == request
        assert token_uri == credentials._token_uri

        # Check that the credentials have the token.
        assert credentials.token == token

        # Check that the credentials are valid (have a token and are not
        # expired)
        assert credentials.valid
