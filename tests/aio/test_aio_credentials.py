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

"""Tests for google.auth.credentials."""

import pytest

from google.auth.aio import credentials


class CredentialsImpl(credentials.Credentials):
    async def refresh(self, request):
        self.token = request


@pytest.mark.asyncio
async def test_before_request():
    credentials = CredentialsImpl()
    request = "token"
    headers = {}

    # First call should call refresh, setting the token.
    await credentials.before_request(request, "http://example.com", "GET", headers)
    assert credentials.valid
    assert credentials.token == "token"
    assert headers["authorization"] == "Bearer token"

    request = "token2"
    headers = {}

    # Second call shouldn't call refresh.
    await credentials.before_request(request, "http://example.com", "GET", headers)
    assert credentials.valid
    assert credentials.token == "token"
    assert headers["authorization"] == "Bearer token"
