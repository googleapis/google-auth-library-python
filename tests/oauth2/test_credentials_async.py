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

import json
import os

import mock
import pytest  # type: ignore

from google.oauth2.aio import credentials as credentials_async


DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

AUTH_USER_JSON_FILE = os.path.join(DATA_DIR, "authorized_user.json")

with open(AUTH_USER_JSON_FILE, "r") as fh:
    AUTH_USER_INFO = json.load(fh)


class TestCredentials(object):

    
    @pytest.mark.asyncio
    def test_default_state(self):
        credentials = (credentials_async.CredentialsBuilder()
                       .setToken(token=None)
                       .build())
        assert credentials.token is None

    @pytest.mark.asyncio
    async def test_token_usage_metrics(self):
        credentials = (credentials_async.CredentialsBuilder()
                       .setToken(token="token")
                       .build())
        headers = {}
        await credentials.before_request(mock.Mock(), None, None, headers)
        assert headers["authorization"] == "Bearer token"
        
        # TODO(ohmayr): The below header can be tested once usage metrics
        # are implemented in google.oauth2.aio.credentials.
        # assert headers["x-goog-api-client"] == "cred-type/u"
