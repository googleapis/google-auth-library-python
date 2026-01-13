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
from unittest import mock

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization
import pytest
import rsa as rsa_lib

from google.auth.crypt import _cryptography_rsa
from google.auth.crypt import _python_rsa
from google.auth.crypt import rsa


DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

with open(os.path.join(DATA_DIR, "privatekey.pem"), "rb") as fh:
    PRIVATE_KEY_BYTES = fh.read()
    CRYPTOGRAPHY_PRIVATE_KEY = serialization.load_pem_private_key(
        PRIVATE_KEY_BYTES, password=None, backend=backends.default_backend()
    )
    RSA_PRIVATE_KEY = rsa_lib.PrivateKey.load_pkcs1(PRIVATE_KEY_BYTES)

with open(os.path.join(DATA_DIR, "privatekey.pub"), "rb") as fh:
    PUBLIC_KEY_BYTES = fh.read()
    CRYPTOGRAPHY_PUBLIC_KEY = serialization.load_pem_public_key(
        PUBLIC_KEY_BYTES, backend=backends.default_backend()
    )
    RSA_PUBLIC_KEY = rsa_lib.PublicKey.load_pkcs1(PUBLIC_KEY_BYTES)


class TestRSAVerifier:
    def test_init_with_cryptography_key(self):
        verifier = rsa.RSAVerifier(CRYPTOGRAPHY_PUBLIC_KEY)
        assert isinstance(verifier._impl, _cryptography_rsa.RSAVerifier)
        assert verifier._impl._pubkey == CRYPTOGRAPHY_PUBLIC_KEY

    def test_init_with_rsa_key(self):
        verifier = rsa.RSAVerifier(RSA_PUBLIC_KEY)
        assert isinstance(verifier._impl, _python_rsa.RSAVerifier)
        assert verifier._impl._pubkey == RSA_PUBLIC_KEY

    def test_warning_with_rsa(self):
        with pytest.warns(DeprecationWarning, match="The 'rsa' library is deprecated"):
            rsa.RSAVerifier(RSA_PUBLIC_KEY)

    def test_init_with_unknown_key(self):
        unknown_key = object()

        with pytest.raises(ValueError):
            rsa.RSAVerifier(unknown_key)

    def test_verify_delegates(self):
        verifier = rsa.RSAVerifier(CRYPTOGRAPHY_PUBLIC_KEY)

        # Mock the implementation's verify method
        with mock.patch.object(
            verifier._impl, "verify", return_value=True
        ) as mock_verify:
            result = verifier.verify(b"message", b"signature")
            assert result is True
            mock_verify.assert_called_once_with(b"message", b"signature")

    @mock.patch("google.auth.crypt.rsa._cryptography_rsa")
    def test_from_string_cryptography(self, mock_crypto):
        expected_verifier = mock.Mock()
        mock_crypto.RSAVerifier.from_string.return_value = expected_verifier

        result = rsa.RSAVerifier.from_string(PUBLIC_KEY_BYTES)

        assert result._impl == expected_verifier
        mock_crypto.RSAVerifier.from_string.assert_called_once_with(PUBLIC_KEY_BYTES)


class TestRSASigner:
    def test_init_with_cryptography_key(self):
        signer = rsa.RSASigner(CRYPTOGRAPHY_PRIVATE_KEY, key_id="123")
        assert isinstance(signer._impl, _cryptography_rsa.RSASigner)
        assert signer._impl._key == CRYPTOGRAPHY_PRIVATE_KEY
        assert signer._impl.key_id == "123"

    def test_init_with_rsa_key(self):
        signer = rsa.RSASigner(RSA_PRIVATE_KEY, key_id="123")
        assert isinstance(signer._impl, _python_rsa.RSASigner)
        assert signer._impl._key == RSA_PRIVATE_KEY
        assert signer._impl.key_id == "123"

    def test_warning_with_rsa(self):
        with pytest.warns(DeprecationWarning, match="The 'rsa' library is deprecated"):
            rsa.RSASigner(RSA_PRIVATE_KEY, key_id="123")

    def test_init_with_unknown_key(self):
        unknown_key = object()

        with pytest.raises(ValueError):
            rsa.RSASigner(unknown_key)

    def test_sign_delegates(self):
        signer = rsa.RSASigner(RSA_PRIVATE_KEY)

        with mock.patch.object(
            signer._impl, "sign", return_value=b"signature"
        ) as mock_sign:
            result = signer.sign(b"message")
            assert result == b"signature"
            mock_sign.assert_called_once_with(b"message")

    @mock.patch("google.auth.crypt.rsa._cryptography_rsa")
    def test_from_string_delegates_to_cryptography(self, mock_crypto):
        expected_signer = mock.Mock()
        mock_crypto.RSASigner.from_string.return_value = expected_signer

        result = rsa.RSASigner.from_string(PRIVATE_KEY_BYTES, key_id="123")

        assert result._impl == expected_signer
        mock_crypto.RSASigner.from_string.assert_called_once_with(
            PRIVATE_KEY_BYTES, key_id="123"
        )

    def test_end_to_end_cryptography_lib(self):
        signer = rsa.RSASigner.from_string(PRIVATE_KEY_BYTES)
        message = b"Hello World"
        sig = signer.sign(message)
        verifier = rsa.RSAVerifier.from_string(PUBLIC_KEY_BYTES)
        result = verifier.verify(message, sig)
        assert result is True
        assert isinstance(verifier._impl, _cryptography_rsa.RSAVerifier)
        assert isinstance(signer._impl, _cryptography_rsa.RSASigner)

    def test_end_to_end_rsa_lib(self):
        signer = rsa.RSASigner(RSA_PRIVATE_KEY)
        message = b"Hello World"
        sig = signer.sign(message)
        verifier = rsa.RSAVerifier(RSA_PUBLIC_KEY)
        result = verifier.verify(message, sig)
        assert bool(result) is True
        assert isinstance(verifier._impl, _python_rsa.RSAVerifier)
        assert isinstance(signer._impl, _python_rsa.RSASigner)
