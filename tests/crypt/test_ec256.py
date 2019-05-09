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

import json
import os

from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from google.auth import _helpers
from google.auth.crypt import base
from google.auth.crypt import ec256


DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')

# To generate ec256_privatekey.pem, ec256_privatekey.pub, and
# ec256_public_cert.pem:
#   $ openssl ecparam -genkey -name prime256v1 -noout -out ec256_privatekey.pem
#   $ openssl ec -in ec256-private-key.pem -pubout -out ec256-publickey.pem
#   $ openssl req -new -x509 -key ec256_privatekey.pem -out \
#   >     ec256_public_cert.pem

with open(os.path.join(DATA_DIR, 'ec256_privatekey.pem'), 'rb') as fh:
    PRIVATE_KEY_BYTES = fh.read()
    PKCS1_KEY_BYTES = PRIVATE_KEY_BYTES

with open(os.path.join(DATA_DIR, 'ec256_publickey.pem'), 'rb') as fh:
    PUBLIC_KEY_BYTES = fh.read()

with open(os.path.join(DATA_DIR, 'ec256_public_cert.pem'), 'rb') as fh:
    PUBLIC_CERT_BYTES = fh.read()

SERVICE_ACCOUNT_JSON_FILE = os.path.join(
    DATA_DIR, 'ec256_service_account.json')

with open(SERVICE_ACCOUNT_JSON_FILE, 'r') as fh:
    SERVICE_ACCOUNT_INFO = json.load(fh)


class TestEC256Verifier(object):
    def test_verify_success(self):
        to_sign = b'foo'
        signer = ec256.EC256Signer.from_string(PRIVATE_KEY_BYTES)
        actual_signature = signer.sign(to_sign)

        verifier = ec256.EC256Verifier.from_string(PUBLIC_KEY_BYTES)
        assert verifier.verify(to_sign, actual_signature)

    def test_verify_unicode_success(self):
        to_sign = u'foo'
        signer = ec256.EC256Signer.from_string(PRIVATE_KEY_BYTES)
        actual_signature = signer.sign(to_sign)

        verifier = ec256.EC256Verifier.from_string(PUBLIC_KEY_BYTES)
        assert verifier.verify(to_sign, actual_signature)

    def test_verify_failure(self):
        verifier = ec256.EC256Verifier.from_string(PUBLIC_KEY_BYTES)
        bad_signature1 = b''
        assert not verifier.verify(b'foo', bad_signature1)
        bad_signature2 = b'a'
        assert not verifier.verify(b'foo', bad_signature2)

    def test_from_string_pub_key(self):
        verifier = ec256.EC256Verifier.from_string(PUBLIC_KEY_BYTES)
        assert isinstance(verifier, ec256.EC256Verifier)
        assert isinstance(verifier._pubkey, ec.EllipticCurvePublicKey)

    def test_from_string_pub_key_unicode(self):
        public_key = _helpers.from_bytes(PUBLIC_KEY_BYTES)
        verifier = ec256.EC256Verifier.from_string(public_key)
        assert isinstance(verifier, ec256.EC256Verifier)
        assert isinstance(verifier._pubkey, ec.EllipticCurvePublicKey)

    def test_from_string_pub_cert(self):
        verifier = ec256.EC256Verifier.from_string(PUBLIC_CERT_BYTES)
        assert isinstance(verifier, ec256.EC256Verifier)
        assert isinstance(verifier._pubkey, ec.EllipticCurvePublicKey)

    def test_from_string_pub_cert_unicode(self):
        public_cert = _helpers.from_bytes(PUBLIC_CERT_BYTES)
        verifier = ec256.EC256Verifier.from_string(public_cert)
        assert isinstance(verifier, ec256.EC256Verifier)
        assert isinstance(verifier._pubkey, ec.EllipticCurvePublicKey)


class TestRSASigner(object):
    def test_from_string_pkcs1(self):
        signer = ec256.EC256Signer.from_string(PKCS1_KEY_BYTES)
        assert isinstance(signer, ec256.EC256Signer)
        assert isinstance(signer._key, ec.EllipticCurvePrivateKey)

    def test_from_string_pkcs1_unicode(self):
        key_bytes = _helpers.from_bytes(PKCS1_KEY_BYTES)
        signer = ec256.EC256Signer.from_string(key_bytes)
        assert isinstance(signer, ec256.EC256Signer)
        assert isinstance(signer._key, ec.EllipticCurvePrivateKey)

    def test_from_string_bogus_key(self):
        key_bytes = 'bogus-key'
        with pytest.raises(ValueError):
            ec256.EC256Signer.from_string(key_bytes)

    def test_from_service_account_info(self):
        signer = ec256.EC256Signer.from_service_account_info(
            SERVICE_ACCOUNT_INFO)

        assert signer.key_id == SERVICE_ACCOUNT_INFO[
            base._JSON_FILE_PRIVATE_KEY_ID]
        assert isinstance(signer._key, ec.EllipticCurvePrivateKey)

    def test_from_service_account_info_missing_key(self):
        with pytest.raises(ValueError) as excinfo:
            ec256.EC256Signer.from_service_account_info({})

        assert excinfo.match(base._JSON_FILE_PRIVATE_KEY)

    def test_from_service_account_file(self):
        signer = ec256.EC256Signer.from_service_account_file(
            SERVICE_ACCOUNT_JSON_FILE)

        assert signer.key_id == SERVICE_ACCOUNT_INFO[
            base._JSON_FILE_PRIVATE_KEY_ID]
        assert isinstance(signer._key, ec.EllipticCurvePrivateKey)
