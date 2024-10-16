# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import grpc
from google.auth import credentials, default
import re
import pytest
from google import showcase

UUID4_RE = r"[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}"

@pytest.fixture
def echo():
    # Create an instance of the Showcase Echo client
    # transport_cls = showcase.EchoClient.get_transport_class("grpc")
    # transport = transport_cls(
    #     credentials=default()[0],
    #     channel=grpc.insecure_channel("localhost:7469"),
    #     host="localhost:7469",
    # )

    transport_cls = showcase.EchoClient.get_transport_class("rest")
    transport = transport_cls(
        credentials=default()[0],
        host="localhost:7469",
        url_scheme="http",
    )

    echo_client = showcase.EchoClient(transport=transport)
    yield echo_client
    # Optional: Clean up resources if needed after the test
    # e.g., echo_client.close()

def test_ssj_with_scopes(echo):
    response = echo.echo_authentication(
        showcase.EchoAuthenticationRequest(
        )
    )

    # Handle the response
    print(response)