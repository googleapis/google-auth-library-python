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
import os

import mock
import pytest
from six.moves import http_client
from six.moves import reload_module
from six.moves.urllib import parse as urlparse

from google.auth import _helpers
from google.auth import crypt
from google.auth import environment_vars
from google.auth import exceptions
from google.auth import jwt
from google.auth import transport
from google.auth.compute_engine import _metadata

PATH = 'instance/service-accounts/default'

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')

with open(os.path.join(DATA_DIR, 'privatekey.pem'), 'rb') as fh:
    PRIVATE_KEY_BYTES = fh.read()

with open(os.path.join(DATA_DIR, 'public_cert.pem'), 'rb') as fh:
    PUBLIC_CERT_BYTES = fh.read()

with open(os.path.join(DATA_DIR, 'other_cert.pem'), 'rb') as fh:
    OTHER_CERT_BYTES = fh.read()

SERVICE_ACCOUNT_JSON_FILE = os.path.join(DATA_DIR, 'service_account.json')

with open(SERVICE_ACCOUNT_JSON_FILE, 'r') as fh:
    SERVICE_ACCOUNT_INFO = json.load(fh)


@pytest.fixture
def signer():
    return crypt.RSASigner.from_string(PRIVATE_KEY_BYTES, '1')


@pytest.fixture
def token_factory(signer):
    def factory(claims=None, use_full_format=False, include_license=False):
        now = _helpers.datetime_to_secs(_helpers.utcnow())
        payload = {
            'aud': 'https://example.com',
            'iat': now,
            'exp': now + 300
        }
        payload.update(claims or {})
        extended_format = {}
        if use_full_format:
            extended_format = {
                "google": {
                    "compute_engine": {
                        "project_id": "foo"
                    }
                }
            }
        if include_license:
            extended_format = {
                "google": {
                    "compute_engine": {
                        "project_id": "foo",
                        "license_id": [
                            "bar"
                            ]
                    }
                }
            }
        payload.update(extended_format)
        return jwt.encode(signer, payload)
    return factory


def make_request(data, status=http_client.OK, headers=None):
    response = mock.create_autospec(transport.Response, instance=True)
    response.status = status
    response.data = _helpers.to_bytes(data)
    response.headers = headers or {}

    request = mock.create_autospec(transport.Request)
    request.return_value = response

    return request


def test_ping_success():
    request = make_request('', headers=_metadata._METADATA_HEADERS)

    assert _metadata.ping(request)

    request.assert_called_once_with(
        method='GET',
        url=_metadata._METADATA_IP_ROOT,
        headers=_metadata._METADATA_HEADERS,
        timeout=_metadata._METADATA_DEFAULT_TIMEOUT)


def test_ping_failure_bad_flavor():
    request = make_request(
        '', headers={_metadata._METADATA_FLAVOR_HEADER: 'meep'})

    assert not _metadata.ping(request)


def test_ping_failure_connection_failed():
    request = make_request('')
    request.side_effect = exceptions.TransportError()

    assert not _metadata.ping(request)


def test_ping_success_custom_root():
    request = make_request('', headers=_metadata._METADATA_HEADERS)

    fake_ip = '1.2.3.4'
    os.environ[environment_vars.GCE_METADATA_IP] = fake_ip
    reload_module(_metadata)

    try:
        assert _metadata.ping(request)
    finally:
        del os.environ[environment_vars.GCE_METADATA_IP]
        reload_module(_metadata)

    request.assert_called_once_with(
        method='GET',
        url='http://' + fake_ip,
        headers=_metadata._METADATA_HEADERS,
        timeout=_metadata._METADATA_DEFAULT_TIMEOUT)


def test_get_success_json():
    key, value = 'foo', 'bar'

    data = json.dumps({key: value})
    request = make_request(
        data, headers={'content-type': 'application/json'})

    result = _metadata.get(request, PATH)

    request.assert_called_once_with(
        method='GET',
        url=_metadata._METADATA_ROOT + PATH,
        headers=_metadata._METADATA_HEADERS)
    assert result[key] == value


def test_get_success_text():
    data = 'foobar'
    request = make_request(data, headers={'content-type': 'text/plain'})

    result = _metadata.get(request, PATH)

    request.assert_called_once_with(
        method='GET',
        url=_metadata._METADATA_ROOT + PATH,
        headers=_metadata._METADATA_HEADERS)
    assert result == data


def test_get_success_custom_root():
    request = make_request(
        '{}', headers={'content-type': 'application/json'})

    fake_root = 'another.metadata.service'
    os.environ[environment_vars.GCE_METADATA_ROOT] = fake_root
    reload_module(_metadata)

    try:
        _metadata.get(request, PATH)
    finally:
        del os.environ[environment_vars.GCE_METADATA_ROOT]
        reload_module(_metadata)

    request.assert_called_once_with(
        method='GET',
        url='http://{}/computeMetadata/v1/{}'.format(fake_root, PATH),
        headers=_metadata._METADATA_HEADERS)


def test_get_failure():
    request = make_request(
        'Metadata error', status=http_client.NOT_FOUND)

    with pytest.raises(exceptions.TransportError) as excinfo:
        _metadata.get(request, PATH)

    assert excinfo.match(r'Metadata error')

    request.assert_called_once_with(
        method='GET',
        url=_metadata._METADATA_ROOT + PATH,
        headers=_metadata._METADATA_HEADERS)


def test_get_failure_bad_json():
    request = make_request(
        '{', headers={'content-type': 'application/json'})

    with pytest.raises(exceptions.TransportError) as excinfo:
        _metadata.get(request, PATH)

    assert excinfo.match(r'invalid JSON')

    request.assert_called_once_with(
        method='GET',
        url=_metadata._METADATA_ROOT + PATH,
        headers=_metadata._METADATA_HEADERS)


def test_get_project_id():
    project = 'example-project'
    request = make_request(
        project, headers={'content-type': 'text/plain'})

    project_id = _metadata.get_project_id(request)

    request.assert_called_once_with(
        method='GET',
        url=_metadata._METADATA_ROOT + 'project/project-id',
        headers=_metadata._METADATA_HEADERS)
    assert project_id == project


@mock.patch('google.auth._helpers.utcnow', return_value=datetime.datetime.min)
def test_get_service_account_token(utcnow):
    ttl = 500
    request = make_request(
        json.dumps({'access_token': 'token', 'expires_in': ttl}),
        headers={'content-type': 'application/json'})

    token, expiry = _metadata.get_service_account_token(request)

    request.assert_called_once_with(
        method='GET',
        url=_metadata._METADATA_ROOT + PATH + '/token',
        headers=_metadata._METADATA_HEADERS)
    assert token == 'token'
    assert expiry == utcnow() + datetime.timedelta(seconds=ttl)


def test_get_id_token_default(token_factory):
    service_account = 'default'
    target_audience = 'https://example.com'

    expire_at = _helpers.datetime_to_secs(
        _helpers.utcnow() + datetime.timedelta(hours=1))
    claims = {'exp': expire_at, 'aud': target_audience}

    tok = token_factory(claims=claims)

    request = make_request(
        tok,
        headers={'content-type': 'text/html'})

    token, expiry = _metadata.get_id_token(
      request, service_account=service_account,
      target_audience=target_audience)

    base_url = urlparse.urljoin(_metadata._METADATA_ROOT, PATH + '/identity')
    query_params = {'format': 'standard', 'licenses': False,
                    'audience': target_audience}
    url = _helpers.update_query(base_url, query_params)

    request.assert_called_once_with(
        method='GET',
        url=url,
        headers=_metadata._METADATA_HEADERS)

    assert token == tok.decode("utf-8")
    assert expiry == datetime.datetime.utcfromtimestamp(expire_at)


def test_get_id_token_full(token_factory):
    service_account = 'default'
    target_audience = 'https://example.com'

    expire_at = _helpers.datetime_to_secs(
        _helpers.utcnow() + datetime.timedelta(hours=1))
    claims = {'exp': expire_at, 'aud': target_audience}

    tok = token_factory(claims=claims, use_full_format=True)

    request = make_request(
        tok,
        headers={'content-type': 'text/html'})

    token, expiry = _metadata.get_id_token(
      request, service_account=service_account,
      target_audience=target_audience, token_format="full",
      include_license=False)

    base_url = urlparse.urljoin(_metadata._METADATA_ROOT, PATH + '/identity')
    query_params = {'format': 'full', 'licenses': False,
                    'audience': target_audience}
    url = _helpers.update_query(base_url, query_params)

    request.assert_called_once_with(
        method='GET',
        url=url,
        headers=_metadata._METADATA_HEADERS)

    assert token == tok.decode("utf-8")
    assert expiry == datetime.datetime.utcfromtimestamp(expire_at)


def test_get_id_token_with_license(token_factory):
    service_account = 'default'
    target_audience = 'https://example.com'

    expire_at = _helpers.datetime_to_secs(
        _helpers.utcnow() + datetime.timedelta(hours=1))
    claims = {'exp': expire_at, 'aud': target_audience}

    tok = token_factory(claims=claims, include_license=True)

    request = make_request(
        tok,
        headers={'content-type': 'text/html'})

    token, expiry = _metadata.get_id_token(
      request, service_account=service_account,
      target_audience=target_audience, token_format="full",
      include_license=True)

    base_url = urlparse.urljoin(_metadata._METADATA_ROOT, PATH + '/identity')
    query_params = {'format': 'full', 'licenses': True,
                    'audience': target_audience}
    url = _helpers.update_query(base_url, query_params)

    request.assert_called_once_with(
        method='GET',
        url=url,
        headers=_metadata._METADATA_HEADERS)

    assert token == tok.decode("utf-8")
    assert expiry == datetime.datetime.utcfromtimestamp(expire_at)


def test_get_service_account_info():
    key, value = 'foo', 'bar'
    request = make_request(
        json.dumps({key: value}),
        headers={'content-type': 'application/json'})

    info = _metadata.get_service_account_info(request)

    request.assert_called_once_with(
        method='GET',
        url=_metadata._METADATA_ROOT + PATH + '/?recursive=true',
        headers=_metadata._METADATA_HEADERS)

    assert info[key] == value
