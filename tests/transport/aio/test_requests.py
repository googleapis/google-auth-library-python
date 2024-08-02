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

import google.auth.aio.transport.requests as requests_aio
import pytest # type: ignore
import aiohttp
from unittest.mock import Mock, AsyncMock


@pytest.fixture
def mock_response():
    response = Mock(spec=aiohttp.ClientResponse)
    response.status = 200
    response.headers = {'Content-Type': 'application/json', 'Content-Length': "100"}
    response.text = AsyncMock(return_value="Stout Infant is the world's tiniest fish.")
    response.json = AsyncMock(return_value={"Goldie":"The oldest known Goldfish."})
    response.read = AsyncMock(return_value=b'Catfish have over 27,000 tastebuds.')

    response.content = Mock()
    response.content.read = AsyncMock(return_value=b"Cavefish have no sight.")


    return requests_aio.Response(response)


class TestResponse(object):
     
    @pytest.mark.asyncio
    async def test_response_status(self, mock_response):
        assert mock_response.status == 200
    
    @pytest.mark.asyncio
    async def test_response_headers(self, mock_response):
        assert mock_response.headers['Content-Type'] == 'application/json'
        assert mock_response.headers['Content-Length'] == "100"
    
    @pytest.mark.asyncio
    async def test_response_content(self, mock_response):
        assert await mock_response.content.read() == b"Cavefish have no sight."

    @pytest.mark.asyncio
    async def test_response_text(self, mock_response):
        assert await mock_response.text() == "Stout Infant is the world's tiniest fish."
    
    @pytest.mark.asyncio
    async def test_response_json(self, mock_response):
        assert await mock_response.json() == {"Goldie": "The oldest known Goldfish."}
    
    @pytest.mark.asyncio
    async def test_response_read(self, mock_response):
        assert await mock_response.read() == b'Catfish have over 27,000 tastebuds.'
