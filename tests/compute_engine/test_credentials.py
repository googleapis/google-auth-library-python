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

from google.auth import _helpers
from google.auth import crypt
from google.auth import exceptions
from google.auth import jwt
from google.auth import transport
from google.auth.compute_engine import credentials

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


class TestCredentials(object):
    credentials = None

    @pytest.fixture(autouse=True)
    def credentials_fixture(self):
        self.credentials = credentials.Credentials()

    def test_default_state(self):
        assert not self.credentials.valid
        # Expiration hasn't been set yet
        assert not self.credentials.expired
        # Scopes aren't needed
        assert not self.credentials.requires_scopes
        # Service account email hasn't been populated
        assert self.credentials.service_account_email == 'default'

    @mock.patch(
        'google.auth._helpers.utcnow',
        return_value=datetime.datetime.min + _helpers.CLOCK_SKEW)
    @mock.patch('google.auth.compute_engine._metadata.get', autospec=True)
    def test_refresh_success(self, get, utcnow):
        get.side_effect = [{
            # First request is for sevice account info.
            'email': 'service-account@example.com',
            'scopes': ['one', 'two']
        }, {
            # Second request is for the token.
            'access_token': 'token',
            'expires_in': 500
        }]

        # Refresh credentials
        self.credentials.refresh(None)

        # Check that the credentials have the token and proper expiration
        assert self.credentials.token == 'token'
        assert self.credentials.expiry == (
            utcnow() + datetime.timedelta(seconds=500))

        # Check the credential info
        assert (self.credentials.service_account_email ==
                'service-account@example.com')
        assert self.credentials._scopes == ['one', 'two']

        # Check that the credentials are valid (have a token and are not
        # expired)
        assert self.credentials.valid

    @mock.patch('google.auth.compute_engine._metadata.get', autospec=True)
    def test_refresh_error(self, get):
        get.side_effect = exceptions.TransportError('http error')

        with pytest.raises(exceptions.RefreshError) as excinfo:
            self.credentials.refresh(None)

        assert excinfo.match(r'http error')

    @mock.patch('google.auth.compute_engine._metadata.get', autospec=True)
    def test_before_request_refreshes(self, get):
        get.side_effect = [{
            # First request is for sevice account info.
            'email': 'service-account@example.com',
            'scopes': 'one two'
        }, {
            # Second request is for the token.
            'access_token': 'token',
            'expires_in': 500
        }]

        # Credentials should start as invalid
        assert not self.credentials.valid

        # before_request should cause a refresh
        request = mock.create_autospec(transport.Request, instance=True)
        self.credentials.before_request(
            request, 'GET', 'http://example.com?a=1#3', {})

        # The refresh endpoint should've been called.
        assert get.called

        # Credentials should now be valid.
        assert self.credentials.valid


class TestIDTokenCredentials(object):
    credentials = None
    test_audience = 'https://example.com'

    @mock.patch('google.auth.compute_engine._metadata.get', autospec=True)
    def test_default_state(self, get):
        get.side_effect = [{
            'email': 'service-account@example.com',
            'scope': ['one', 'two'],
        }]

        request = mock.create_autospec(transport.Request, instance=True)
        self.credentials = credentials.IDTokenCredentials(
            request=request, target_audience="https://example.com")

        assert not self.credentials.valid
        # Expiration hasn't been set yet
        assert not self.credentials.expired
        # Service account email hasn't been populated
        assert (self.credentials.service_account_email
                == 'service-account@example.com')
        # Signer is initialized
        assert self.credentials.signer
        assert self.credentials.signer_email == 'service-account@example.com'

    @mock.patch('google.auth.compute_engine._metadata.get', autospec=True)
    def test_with_target_audience(self, get, token_factory):
        expire_at = _helpers.datetime_to_secs(
            _helpers.utcnow() + datetime.timedelta(hours=1))
        claims = {'exp': expire_at, 'aud': self.test_audience}

        tok = token_factory(claims=claims)

        get.side_effect = [{
            'email': 'service-account@example.com',
            'scopes': ['one', 'two']
        }, tok]

        request = mock.create_autospec(transport.Request, instance=True)
        self.credentials = credentials.IDTokenCredentials(
            request=request, target_audience=None)
        self.credentials = (
            self.credentials.with_target_audience(self.test_audience))

        self.credentials.refresh(None)
        token = self.credentials.token
        payload = jwt.decode(token, verify=False)

        assert self.credentials.token == tok
        assert self.credentials.expiry == (
            datetime.datetime.utcfromtimestamp(expire_at))
        assert payload['aud'] == self.test_audience
        assert self.credentials.valid

    @mock.patch('google.auth.compute_engine._metadata.get', autospec=True)
    def test_refresh_success(self, get, token_factory):
        expire_at = _helpers.datetime_to_secs(
            _helpers.utcnow() + datetime.timedelta(hours=1))
        claims = {'exp': expire_at, 'aud': self.test_audience}

        tok = token_factory(claims=claims)

        get.side_effect = [{
            'email': 'service-account@example.com',
            'scopes': ['one', 'two']
        },  tok]

        request = mock.create_autospec(transport.Request, instance=True)
        self.credentials = credentials.IDTokenCredentials(
            request=request, target_audience=None)

        self.credentials.refresh(None)
        token = self.credentials.token
        payload = jwt.decode(token, verify=False)

        assert self.credentials.token == tok
        assert self.credentials.expiry == (
            datetime.datetime.utcfromtimestamp(expire_at))
        assert payload['aud'] == self.test_audience

        assert self.credentials.valid

    @mock.patch('google.auth.compute_engine._metadata.get', autospec=True)
    def test_refresh_error(self, get):
        get.side_effect = [{
            'email': 'service-account@example.com',
            'scopes': ['one', 'two']
        }, exceptions.TransportError('not found')]

        request = mock.create_autospec(transport.Request, instance=True)
        self.credentials = credentials.IDTokenCredentials(
            request=request, target_audience=self.test_audience)

        with pytest.raises(exceptions.TransportError) as excinfo:
            self.credentials.refresh(None)

        assert excinfo.match(r'not found')

    @mock.patch('google.auth.compute_engine._metadata.get', autospec=True)
    def test_before_request_refreshes(self, get, token_factory):
        expire_at = _helpers.datetime_to_secs(
            _helpers.utcnow() + datetime.timedelta(hours=1))
        claims = {'exp': expire_at, 'aud': self.test_audience}

        tok = token_factory(claims=claims)

        get.side_effect = [{
            'email': 'service-account@example.com',
            'scopes': ['one', 'two']
        },  tok]

        request = mock.create_autospec(transport.Request, instance=True)
        self.credentials = credentials.IDTokenCredentials(
            request=request, target_audience=None)

        # Credentials should start as invalid
        assert not self.credentials.valid

        # before_request should cause a refresh
        request = mock.create_autospec(transport.Request, instance=True)
        self.credentials.before_request(
            request, 'GET', 'http://example.com?a=1#3', {})

        # The refresh endpoint should've been called.
        assert get.called

        # Credentials should now be valid.
        assert self.credentials.valid

    @mock.patch('google.auth.compute_engine._metadata.get', autospec=True)
    @mock.patch('google.auth.iam.Signer.sign', autospec=True)
    def test_sign_bytes(self, sign, get):
        get.side_effect = [{
            'email': 'service-account@example.com',
            'scopes': ['one', 'two']
        }]
        sign.side_effect = [b'signature']

        request = mock.create_autospec(transport.Request, instance=True)
        response = mock.Mock()
        response.data = b'{"signature": "c2lnbmF0dXJl"}'
        response.status = 200
        request.side_effect = [response]

        self.credentials = credentials.IDTokenCredentials(
            request=request, target_audience="https://audience.com")

        # Generate authorization grant:
        signature = self.credentials.sign_bytes(b"some bytes")

        # The JWT token signature is 'signature' encoded in base 64:
        assert signature == b'signature'

    @mock.patch('google.auth.compute_engine._metadata.get', autospec=True)
    def test_with_token_format(self, get, token_factory):
        expire_at = _helpers.datetime_to_secs(
            _helpers.utcnow() + datetime.timedelta(hours=1))

        claims = {'exp': expire_at, 'aud': self.test_audience}

        tok = token_factory(claims=claims, use_full_format=True)

        get.side_effect = [{
            'email': 'service-account@example.com',
            'scopes': ['one', 'two']
        }, tok]

        request = mock.create_autospec(transport.Request, instance=True)
        self.credentials = credentials.IDTokenCredentials(
            request=request, target_audience=None)
        self.credentials = (
            self.credentials.with_token_format('full'))

        self.credentials.refresh(None)
        token = self.credentials.token
        payload = jwt.decode(token, verify=False)

        assert self.credentials.token == tok
        assert self.credentials.expiry == (
            datetime.datetime.utcfromtimestamp(expire_at))
        assert payload['google'] == {
            'compute_engine': {
                'project_id': 'foo'
            }
        }
        assert self.credentials.valid

    @mock.patch('google.auth.compute_engine._metadata.get', autospec=True)
    def test_with_license(self, get, token_factory):
        expire_at = _helpers.datetime_to_secs(
            _helpers.utcnow() + datetime.timedelta(hours=1))

        claims = {'exp': expire_at, 'aud': self.test_audience}

        tok = token_factory(claims=claims, use_full_format=True,
                            include_license=True)

        get.side_effect = [{
            'email': 'service-account@example.com',
            'scopes': ['one', 'two']
        }, tok]

        request = mock.create_autospec(transport.Request, instance=True)
        self.credentials = credentials.IDTokenCredentials(
            request=request, target_audience=None)
        self.credentials = (
            self.credentials.with_license(True))
        self.credentials.refresh(None)
        token = self.credentials.token
        payload = jwt.decode(token, verify=False)

        assert self.credentials.token == tok
        assert self.credentials.expiry == (
            datetime.datetime.utcfromtimestamp(expire_at))
        assert payload['google']['compute_engine']['license_id'] == [
                'bar'
            ]
        assert self.credentials.valid
