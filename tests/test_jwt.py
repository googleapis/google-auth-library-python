# Copyright 2014 Google Inc. All rights reserved.
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

import base64
import datetime
import json
import os

import mock
import pytest

from google.auth import _helpers
from google.auth import crypt
from google.auth import jwt


DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

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
    return crypt.Signer.from_string(PRIVATE_KEY_BYTES, '1')


def test_encode_basic(signer):
    test_payload = {'test': 'value'}
    encoded = jwt.encode(signer, test_payload)
    header, payload, _, _ = jwt._unverified_decode(encoded)
    assert payload == test_payload
    assert header == {'typ': 'JWT', 'alg': 'RS256', 'kid': signer.key_id}


def test_encode_extra_headers(signer):
    encoded = jwt.encode(signer, {}, header={'extra': 'value'})
    header = jwt.decode_header(encoded)
    assert header == {
        'typ': 'JWT', 'alg': 'RS256', 'kid': signer.key_id, 'extra': 'value'}


@pytest.fixture
def token_factory(signer):
    def factory(claims=None, key_id=None):
        now = _helpers.datetime_to_secs(_helpers.now())
        payload = {
            'aud': 'audience@example.com',
            'iat': now,
            'exp': now + 300,
            'user': 'billy bob',
            'metadata': {'meta': 'data'}
        }
        payload.update(claims or {})
        return jwt.encode(signer, payload, key_id=key_id)
    return factory


def test_decode_valid(token_factory):
    payload = jwt.decode(token_factory(), certs=PUBLIC_CERT_BYTES)
    assert payload['aud'] == 'audience@example.com'
    assert payload['user'] == 'billy bob'
    assert payload['metadata']['meta'] == 'data'


def test_decode_valid_with_audience(token_factory):
    payload = jwt.decode(
        token_factory(), certs=PUBLIC_CERT_BYTES,
        audience='audience@example.com')
    assert payload['aud'] == 'audience@example.com'
    assert payload['user'] == 'billy bob'
    assert payload['metadata']['meta'] == 'data'


def test_decode_valid_unverified(token_factory):
    payload = jwt.decode(token_factory(), certs=OTHER_CERT_BYTES, verify=False)
    assert payload['aud'] == 'audience@example.com'
    assert payload['user'] == 'billy bob'
    assert payload['metadata']['meta'] == 'data'


def test_decode_bad_token_wrong_number_of_segments():
    with pytest.raises(ValueError) as excinfo:
        jwt.decode('1.2', PUBLIC_CERT_BYTES)
    assert excinfo.match(r'Wrong number of segments')


def test_decode_bad_token_not_base64():
    with pytest.raises((ValueError, TypeError)) as excinfo:
        jwt.decode('1.2.3', PUBLIC_CERT_BYTES)
    assert excinfo.match(r'Incorrect padding')


def test_decode_bad_token_not_json():
    token = b'.'.join([base64.urlsafe_b64encode(b'123!')] * 3)
    with pytest.raises(ValueError) as excinfo:
        jwt.decode(token, PUBLIC_CERT_BYTES)
    assert excinfo.match(r'Can\'t parse segment')


def test_decode_bad_token_no_iat_or_exp(signer):
    token = jwt.encode(signer, {'test': 'value'})
    with pytest.raises(ValueError) as excinfo:
        jwt.decode(token, PUBLIC_CERT_BYTES)
    assert excinfo.match(r'Token does not contain required claim')


def test_decode_bad_token_too_early(token_factory):
    token = token_factory(claims={
        'iat': _helpers.datetime_to_secs(
            _helpers.now() + datetime.timedelta(hours=1))
    })
    with pytest.raises(ValueError) as excinfo:
        jwt.decode(token, PUBLIC_CERT_BYTES)
    assert excinfo.match(r'Token used too early')


def test_decode_bad_token_expired(token_factory):
    token = token_factory(claims={
        'exp': _helpers.datetime_to_secs(
            _helpers.now() - datetime.timedelta(hours=1))
    })
    with pytest.raises(ValueError) as excinfo:
        jwt.decode(token, PUBLIC_CERT_BYTES)
    assert excinfo.match(r'Token expired')


def test_decode_bad_token_wrong_audience(token_factory):
    token = token_factory()
    audience = 'audience2@example.com'
    with pytest.raises(ValueError) as excinfo:
        jwt.decode(token, PUBLIC_CERT_BYTES, audience=audience)
    assert excinfo.match(r'Token has wrong audience')


def test_decode_wrong_cert(token_factory):
    with pytest.raises(ValueError) as excinfo:
        jwt.decode(token_factory(), OTHER_CERT_BYTES)
    assert excinfo.match(r'Could not verify token signature')


def test_decode_multicert_bad_cert(token_factory):
    certs = {'1': OTHER_CERT_BYTES, '2': PUBLIC_CERT_BYTES}
    with pytest.raises(ValueError) as excinfo:
        jwt.decode(token_factory(), certs)
    assert excinfo.match(r'Could not verify token signature')


def test_decode_no_cert(token_factory):
    certs = {'2': PUBLIC_CERT_BYTES}
    with pytest.raises(ValueError) as excinfo:
        jwt.decode(token_factory(), certs)
    assert excinfo.match(r'Certificate for key id 1 not found')


def test_decode_no_key_id(token_factory):
    token = token_factory(key_id=False)
    certs = {'2': PUBLIC_CERT_BYTES}
    payload = jwt.decode(token, certs)
    assert payload['user'] == 'billy bob'


class TestCredentials:
    service_account_email = 'service-account@example.com'

    @pytest.fixture(autouse=True)
    def credentials(self, signer):
        self.credentials = jwt.Credentials(
            signer, self.service_account_email)

    def test_from_service_account_info(self):
        with open(SERVICE_ACCOUNT_JSON_FILE, 'r') as fh:
            info = json.load(fh)

        credentials = jwt.Credentials.from_service_account_info(info)

        assert credentials._signer.key_id == info['private_key_id']
        assert credentials._issuer == info['client_email']
        assert credentials._subject == info['client_email']

    def test_from_service_account_info_args(self):
        info = dict(SERVICE_ACCOUNT_INFO)

        credentials = jwt.Credentials.from_service_account_info(
            info, subject='subject', audience='audience',
            additional_claims={'meta': 'data'})

        assert credentials._signer.key_id == info['private_key_id']
        assert credentials._issuer == info['client_email']
        assert credentials._subject == 'subject'
        assert credentials._audience == 'audience'
        assert credentials._additional_claims['meta'] == 'data'

    def test_from_service_account_bad_key(self):
        info = dict(SERVICE_ACCOUNT_INFO)
        info['private_key'] = 'garbage'

        with pytest.raises(ValueError) as excinfo:
            jwt.Credentials.from_service_account_info(info)

        assert excinfo.match(r'No key could be detected')

    def test_from_service_account_bad_format(self):
        info = {}

        with pytest.raises(KeyError):
            jwt.Credentials.from_service_account_info(info)

    def test_from_service_account_file(self):
        info = dict(SERVICE_ACCOUNT_INFO)

        credentials = jwt.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_JSON_FILE)

        assert credentials._signer.key_id == info['private_key_id']
        assert credentials._issuer == info['client_email']
        assert credentials._subject == info['client_email']

    def test_from_service_account_file_args(self):
        info = dict(SERVICE_ACCOUNT_INFO)

        credentials = jwt.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_JSON_FILE, subject='subject', audience='audience',
            additional_claims={'meta': 'data'})

        assert credentials._signer.key_id == info['private_key_id']
        assert credentials._issuer == info['client_email']
        assert credentials._subject == 'subject'
        assert credentials._audience == 'audience'
        assert credentials._additional_claims['meta'] == 'data'

    def test_default_state(self):
        assert not self.credentials.valid
        # Expiration hasn't been set yet
        assert not self.credentials.expired

    def test_sign_bytes(self):
        to_sign = b'123'
        signature = self.credentials.sign_bytes(to_sign)
        crypt.verify_signature(to_sign, signature, PUBLIC_CERT_BYTES)

    def _verify_token(self, token):
        payload = jwt.decode(token, PUBLIC_CERT_BYTES)
        assert payload['iss'] == self.service_account_email
        return payload

    def test_refresh(self):
        self.credentials.refresh(None)
        assert self.credentials.valid
        assert not self.credentials.expired

    def test_expired(self):
        assert not self.credentials.expired

        self.credentials.refresh(None)
        assert not self.credentials.expired

        with mock.patch('google.auth._helpers.now') as now:
            one_day_from_now = datetime.timedelta(days=1)
            now.return_value = self.credentials.expiry + one_day_from_now
            assert self.credentials.expired

    def test_apply(self):
        headers = {}

        self.credentials.refresh(None)
        self.credentials.apply(headers)

        header_value = headers[b'authorization']
        assert header_value.startswith('Bearer ')

        token = header_value.split().pop()
        self._verify_token(token)

    def test_before_request_one_time_token(self):
        headers = {}

        self.credentials.refresh(None)
        self.credentials.before_request(
            mock.Mock(), 'GET', 'http://example.com?a=1#3', headers)

        header_value = headers[b'authorization']
        token = header_value.split().pop()

        # This should be a one-off token, so it shouldn't be the same as the
        # credentials' stored token.
        assert token != self.credentials.token

        payload = self._verify_token(token)
        assert payload['aud'] == 'http://example.com'

    def test_before_request_set_audience(self):
        headers = {}

        credentials = self.credentials.with_claims(audience='test')
        credentials.refresh(None)
        credentials.before_request(
            mock.Mock(), 'GET', 'http://example.com?a=1#3', headers)

        header_value = headers[b'authorization']
        token = header_value.split().pop()

        # Since the audience is set, it should use the existing token.
        assert token.encode('utf-8') == credentials.token

        payload = self._verify_token(token)
        assert payload['aud'] == 'test'

    def test_before_request_refreshes(self):
        credentials = self.credentials.with_claims(audience='test')
        assert not credentials.valid
        credentials.before_request(
            mock.Mock(), 'GET', 'http://example.com?a=1#3', {})
        assert credentials.valid
