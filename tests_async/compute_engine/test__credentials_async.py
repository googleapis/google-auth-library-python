# Copyright 2023 Google LLC
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

import datetime
from unittest import mock

import pytest
from google.auth import exceptions
from google.auth.compute_engine import _credentials_async


@pytest.fixture
def request_mock():
    return mock.AsyncMock()


@pytest.mark.asyncio
async def test_refresh_success(request_mock):
    creds = _credentials_async.Credentials()

    # Mock retrieve_info and get_token
    with mock.patch(
        "google.auth.compute_engine._metadata_async.get_service_account_info",
        autospec=True,
    ) as get_info, mock.patch(
        "google.auth.compute_engine._metadata_async.get_service_account_token",
        autospec=True,
    ) as get_token:

        get_info.return_value = {"email": "sa@example.com", "scopes": ["scope"]}
        get_token.return_value = ("token", datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None))

        await creds.refresh(request_mock)

        assert creds.token == "token"
        assert creds.service_account_email == "sa@example.com"
        assert creds.scopes == ["scope"]


@pytest.mark.asyncio
async def test_refresh_failure(request_mock):
    creds = _credentials_async.Credentials()

    with mock.patch(
        "google.auth.compute_engine._metadata_async.get_service_account_info",
        side_effect=exceptions.TransportError("error"),
    ):
        with pytest.raises(exceptions.RefreshError):
            await creds.refresh(request_mock)
