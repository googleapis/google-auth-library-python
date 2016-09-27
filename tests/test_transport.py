# Copyright 2016 Google Inc. All rights reserved.
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

import mock
import urllib3

from google.auth import transport


def test__default_http():
    http = transport._default_http()
    assert isinstance(http, urllib3.PoolManager)


def test_request():
    http = mock.Mock()
    transport.request(http, 'a', b='c')
    http.request.assert_called_with('a', b='c')


@mock.patch('google.auth.transport._default_http')
def test_request_no_http(default_http_mock):
    http_mock = mock.Mock()
    default_http_mock.return_value = http_mock

    transport.request(None, 'a', b='c')

    http_mock.request.assert_called_with('a', b='c')
