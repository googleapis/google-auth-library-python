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

import datetime
import json

import mock
import pytest
from six.moves import http_client
from six.moves import urllib

from google.auth import exceptions
from google.oauth2 import _client


def test__handle_error_response():
    response_data = json.dumps({
        'error': 'help',
        'error_description': 'I\'m alive'})

    with pytest.raises(exceptions.RefreshError) as excinfo:
        _client._handle_error_response(response_data)

    assert excinfo.match(r'help: I\'m alive')


def test__handle_error_response_non_json():
    response_data = 'Help, I\'m alive'

    with pytest.raises(exceptions.RefreshError) as excinfo:
        _client._handle_error_response(response_data)

    assert excinfo.match(r'Help, I\'m alive')


@mock.patch('google.auth._helpers.utcnow', return_value=datetime.datetime.min)
def test__parse_expiry(now_mock):
    result = _client._parse_expiry({'expires_in': 500})
    assert result == datetime.datetime.min + datetime.timedelta(seconds=500)


def test__parse_expiry_none():
    assert _client._parse_expiry({}) is None


def test__token_endpoint_request():
    response = mock.Mock()
    response.status = http_client.OK
    response.data = json.dumps({'test': 'response'}).encode('utf-8')
    request = mock.Mock(return_value=response)

    result = _client._token_endpoint_request(
        request, 'http://example.com', {'test': 'params'})

    # Check request call
    request.assert_called_with(
        method='POST',
        url='http://example.com',
        headers={'content-type': 'application/x-www-form-urlencoded'},
        body='test=params')

    # Check result
    assert result == {'test': 'response'}


def test__token_endpoint_request_error():
    response = mock.Mock()
    response.status = http_client.BAD_REQUEST
    response.data = b'Error'
    request = mock.Mock(return_value=response)

    with pytest.raises(exceptions.RefreshError):
        _client._token_endpoint_request(request, 'http://example.com', {})


@mock.patch('google.auth._helpers.utcnow', return_value=datetime.datetime.min)
def test_jwt_grant(now_mock):
    response = mock.Mock()
    response.status = http_client.OK
    response.data = json.dumps({
        'access_token': 'token',
        'expires_in': 500,
        'extra': 'data'}).encode('utf-8')
    request = mock.Mock(return_value=response)

    token, expiry, extra_data = _client.jwt_grant(
        request, 'http://example.com', 'assertion')

    # Check request call
    request_body = request.call_args[1]['body']
    request_params = urllib.parse.parse_qs(request_body)
    assert request_params['grant_type'][0] == _client._JWT_GRANT_TYPE
    assert request_params['assertion'][0] == 'assertion'

    # Check result
    assert token == 'token'
    assert expiry == datetime.datetime.min + datetime.timedelta(seconds=500)
    assert extra_data['extra'] == 'data'


@mock.patch('google.auth._helpers.utcnow', return_value=datetime.datetime.min)
def test_refresh_grant(now_mock):
    response = mock.Mock()
    response.status = http_client.OK
    response.data = json.dumps({
        'access_token': 'token',
        'refresh_token': 'new_refresh_token',
        'expires_in': 500,
        'extra': 'data'}).encode('utf-8')
    request = mock.Mock(return_value=response)

    token, refresh_token, expiry, extra_data = _client.refresh_grant(
        request, 'http://example.com', 'refresh_token', 'client_id',
        'client_secret')

    # Check request call
    request_body = request.call_args[1]['body']
    request_params = urllib.parse.parse_qs(request_body)
    assert request_params['grant_type'][0] == _client._REFRESH_GRANT_TYPE
    assert request_params['refresh_token'][0] == 'refresh_token'
    assert request_params['client_id'][0] == 'client_id'
    assert request_params['client_secret'][0] == 'client_secret'

    # Check result
    assert token == 'token'
    assert refresh_token == 'new_refresh_token'
    assert expiry == datetime.datetime.min + datetime.timedelta(seconds=500)
    assert extra_data['extra'] == 'data'
