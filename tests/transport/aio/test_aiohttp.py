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

import google.auth.aio.transport.aiohttp as auth_aiohttp
import pytest  # type: ignore
import pytest_asyncio
import asyncio
from google.auth import exceptions
from aioresponses import aioresponses

# TODO (ohmayr): Verify if we want to optionally run these test cases
# if aohttp is installed instead of raising an exception.
try:
    import aiohttp
except ImportError as caught_exc:  # pragma: NO COVER
    raise ImportError(
        "The aiohttp library is not installed from please install the aiohttp package to use the aiohttp transport."
    ) from caught_exc


# TODO (ohmayr): Update tests to incorporate custom response.
@pytest.mark.asyncio
class TestRequest:
    @pytest_asyncio.fixture
    async def aiohttp_request(self):
        request = auth_aiohttp.Request()
        yield request
        await request.close()

    async def test_request_call_success(self, aiohttp_request):
        with aioresponses() as m:
            m.get("http://example.com", status=400, body="test")
            response = await aiohttp_request("http://example.com")
            assert response.status == 400

    async def test_request_call_raises_client_error(self, aiohttp_request):
        with aioresponses() as m:
            m.get("http://example.com", exception=aiohttp.ClientError)

            with pytest.raises(exceptions.TransportError):
                response = await aiohttp_request("http://example.com/api")

    async def test_request_call_raises_timeout_error(self, aiohttp_request):
        with aioresponses() as m:
            m.get("http://example.com", exception=asyncio.TimeoutError)

            # TODO(ohmayr): Update this test case to raise custom error
            with pytest.raises(exceptions.TransportError):
                response = await aiohttp_request("http://example.com")
