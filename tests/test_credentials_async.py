# Copyright 2024 Google LLC
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

import pytest  # type: ignore

from google.auth.aio import credentials


class CredentialsImpl(credentials.Credentials):
    pass


def test_credentials_constructor():
    credentials = CredentialsImpl()
    assert not credentials.token


@pytest.mark.asyncio
async def test_before_request():
    credentials = CredentialsImpl()
    request = "token"
    headers = {}
    credentials.token = "orchid"

    # before_request should not affect the value of the token.
    await credentials.before_request(request, "http://example.com", "GET", headers)
    assert credentials.token == "orchid"
    assert headers["authorization"] == "Bearer orchid"
    assert "x-allowed-locations" not in headers

    request = "token2"
    headers = {}
    
    # Second call shouldn't affect token or headers.
    await credentials.before_request(request, "http://example.com", "GET", headers)
    assert credentials.token == "orchid"
    assert headers["authorization"] == "Bearer orchid"
    assert "x-allowed-locations" not in headers


@pytest.mark.asyncio
async def test_static_credentials_before_request():
    static_creds = credentials.StaticCredentials(token="orchid")
    request = "token"
    headers = {}

    # before_request should not affect the value of the token.
    await static_creds.before_request(request, "http://example.com", "GET", headers)
    assert static_creds.token == "orchid"
    assert headers["authorization"] == "Bearer orchid"
    assert "x-allowed-locations" not in headers

    request = "token2"
    headers = {}
    
    # Second call shouldn't affect token or headers.
    await static_creds.before_request(request, "http://example.com", "GET", headers)
    assert static_creds.token == "orchid"
    assert headers["authorization"] == "Bearer orchid"
    assert "x-allowed-locations" not in headers


@pytest.mark.asyncio
async def test_static_credentials_refresh():
    static_creds = credentials.StaticCredentials(token="orchid")
    request = "token"

    with pytest.raises(NotImplementedError) as exc:
        await static_creds.refresh(request)
        assert exc.value == "Refresh is not supported in StaticCredentials."