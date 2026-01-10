# Copyright 2026 Google LLC
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

import os
import pytest
from unittest import mock

from google.auth import exceptions
from google.auth.crypt import rsa
from google.auth.crypt import _python_rsa
try:
    from google.auth.crypt import _cryptography_rsa
except ImportError:
    _cryptography_rsa = None

# Mock objects to simulate keys from different libraries
class MockRsaPublicKey:
    pass

class MockCryptographyPublicKey:
    pass

class MockRsaPrivateKey:
    pass

class MockCryptographyPrivateKey:
    pass

# We need to set the module attributes to match what the code expects
MockRsaPublicKey.__module__ = "rsa.key"
MockCryptographyPublicKey.__module__ = "cryptography.hazmat.primitives.asymmetric.rsa"
MockRsaPrivateKey.__module__ = "rsa.key"
MockCryptographyPrivateKey.__module__ = "cryptography.hazmat.primitives.asymmetric.rsa"

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

with open(os.path.join(DATA_DIR, "privatekey.pem"), "rb") as fh:
    PRIVATE_KEY_BYTES = fh.read()

with open(os.path.join(DATA_DIR, "privatekey.pub"), "rb") as fh:
    PUBLIC_KEY_BYTES = fh.read()

class TestRSAVerifier:
    def test_init_with_cryptography_key(self):
        pub_key = MockCryptographyPublicKey()
        verifier = rsa.RSAVerifier(pub_key)
        assert isinstance(verifier._impl, _cryptography_rsa.RSAVerifier)
        assert verifier._impl._pubkey == pub_key

    def test_init_with_rsa_key(self):
        pub_key = MockRsaPublicKey()
        verifier = rsa.RSAVerifier(pub_key)
        assert isinstance(verifier._impl, _python_rsa.RSAVerifier)
        assert verifier._impl._pubkey == pub_key

    def test_init_with_unknown_key(self):
        pub_key = "not a key"
        with pytest.raises(ValueError): 
             rsa.RSAVerifier(pub_key)

    def test_verify_delegates(self):
        pub_key = MockCryptographyPublicKey()
        verifier = rsa.RSAVerifier(pub_key)

        # Mock the implementation's verify method
        with mock.patch.object(verifier._impl, "verify", return_value=True) as mock_verify:
            result = verifier.verify(b"message", b"signature")
            assert result is True
            mock_verify.assert_called_once_with(b"message", b"signature")

    @mock.patch("google.auth.crypt.rsa._cryptography_rsa")
    def test_from_string_delegates_to_cryptography(self, mock_crypto):
        # Setup mock to return a dummy verifier
        expected_verifier = mock.Mock()
        mock_crypto.RSAVerifier.from_string.return_value = expected_verifier

        result = rsa.RSAVerifier.from_string(PUBLIC_KEY_BYTES)

        assert result == expected_verifier
        mock_crypto.RSAVerifier.from_string.assert_called_once_with(PUBLIC_KEY_BYTES)

    @mock.patch("google.auth.crypt.rsa._cryptography_rsa", None)
    @mock.patch("google.auth.crypt.rsa._python_rsa")
    def test_from_string_delegates_to_python_rsa(self, mock_python_rsa):
        expected_verifier = mock.Mock()
        mock_python_rsa.RSAVerifier.from_string.return_value = expected_verifier

        result = rsa.RSAVerifier.from_string(PUBLIC_KEY_BYTES)

        assert result == expected_verifier
        mock_python_rsa.RSAVerifier.from_string.assert_called_once_with(PUBLIC_KEY_BYTES)

    @mock.patch("google.auth.crypt.rsa._cryptography_rsa", None)
    @mock.patch("google.auth.crypt.rsa._python_rsa", None)
    def test_from_string_missing_deps(self):
        with pytest.raises(exceptions.MissingOptionalDependencyError):
            rsa.RSAVerifier.from_string(PUBLIC_KEY_BYTES)


class TestRSASigner:
    def test_init_with_cryptography_key(self):
        priv_key = MockCryptographyPrivateKey()
        signer = rsa.RSASigner(priv_key, key_id="123")
        assert isinstance(signer._impl, _cryptography_rsa.RSASigner)
        assert signer._impl._key == priv_key
        assert signer._impl.key_id == "123"

    def test_init_with_rsa_key(self):
        priv_key = MockRsaPrivateKey()
        signer = rsa.RSASigner(priv_key, key_id="123")
        assert isinstance(signer._impl, _python_rsa.RSASigner)
        assert signer._impl._key == priv_key
        assert signer._impl.key_id == "123"

    def test_sign_delegates(self):
        priv_key = MockCryptographyPrivateKey()
        signer = rsa.RSASigner(priv_key)

        with mock.patch.object(signer._impl, "sign", return_value=b"signature") as mock_sign:
            result = signer.sign(b"message")
            assert result == b"signature"
            mock_sign.assert_called_once_with(b"message")

    def test_key_id_delegates(self):
        priv_key = MockCryptographyPrivateKey()
        signer = rsa.RSASigner(priv_key, key_id="my-key-id")
        assert signer.key_id == "my-key-id"

    @mock.patch("google.auth.crypt.rsa._cryptography_rsa")
    def test_from_string_delegates_to_cryptography(self, mock_crypto):
        expected_signer = mock.Mock()
        mock_crypto.RSASigner.from_string.return_value = expected_signer

        result = rsa.RSASigner.from_string(PRIVATE_KEY_BYTES, key_id="123")

        assert result == expected_signer
        mock_crypto.RSASigner.from_string.assert_called_once_with(PRIVATE_KEY_BYTES, key_id="123")

    @mock.patch("google.auth.crypt.rsa._cryptography_rsa", None)
    @mock.patch("google.auth.crypt.rsa._python_rsa")
    def test_from_string_delegates_to_python_rsa(self, mock_python_rsa):
        expected_signer = mock.Mock()
        mock_python_rsa.RSASigner.from_string.return_value = expected_signer

        result = rsa.RSASigner.from_string(PRIVATE_KEY_BYTES, key_id="123")

        assert result == expected_signer
        mock_python_rsa.RSASigner.from_string.assert_called_once_with(PRIVATE_KEY_BYTES, key_id="123")
