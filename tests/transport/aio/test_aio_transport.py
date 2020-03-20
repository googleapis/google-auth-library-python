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

"""Tests google.auth.transport.aio"""

import google.auth.transport.aio as aio_transport


def test_response_construction():
    test_status = 200
    test_headers = {"header": "header_value"}
    test_data = b"test_data"
    response = aio_transport.Response(test_status, test_headers, test_data)
    assert response.status == test_status
    assert response.headers == test_headers
    assert response.data == test_data
