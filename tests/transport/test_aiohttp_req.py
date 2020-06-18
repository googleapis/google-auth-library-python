# Copyright 2016 Google LLC
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
import functools
import sys
import asyncio
import aiohttp
import asynctest

import freezegun
import mock
import OpenSSL
import pytest
import requests
import requests.adapters
from six.moves import http_client

from google.auth import exceptions
import google.auth.credentials
import google.auth.transport._mtls_helper
from google.auth.transport import aiohttp_req
from tests.transport import compliance


@pytest.fixture
def frozen_time():
    with freezegun.freeze_time("1970-01-01 00:00:00", tick=False) as frozen:
        yield frozen

class TestRequestResponse(compliance.RequestResponseTests):

    @pytest.mark.asyncio
    def make_request(self):
        return aiohttp_req.Request()

    @pytest.mark.asyncio
    async def test_timeout(self):
        http = asynctest.mock.create_autospec(aiohttp.ClientSession, instance=True)
        #breakpoint()
        request = google.auth.transport.aiohttp_req.Request(http)
        
        await request(url="http://example.com", method="GET", timeout=5)

        assert http.request.call_args[1]["timeout"] == 5

