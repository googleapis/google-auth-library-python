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
"""
RSASigner and RSAVerifier implementation used when neither rsa or cryptography is installed.
Implementation currently raises an ImportError directing user to install an optional dependency
"""


def _build_error(obj_or_cls):
    cls = obj_or_cls if isinstance(obj_or_cls, type) else type(obj_or_cls)
    return ImportError(
        (
            f"{cls.__name__} requires `cryptography` optional dependency.",
            "(Note: 'rsa' is also supported for legacy compatibility but is deprecated).",
        )
    )


class RSAVerifier(base.Verifier):
    """Verifies RSA cryptographic signatures using public keys.

    Args:
        public_key (rsa.key.PublicKey): The public key used to verify
            signatures.
    """

    def __init__(self, public_key):
        raise _build_error(self)

    @_helpers.copy_docstring(base.Verifier)
    def verify(self, message, signature):
        raise _build_error(self)

    @classmethod
    def from_string(cls, public_key):
        """Construct an Verifier instance from a public key or public
        certificate string.

        Args:
            public_key (Union[str, bytes]): The public key in PEM format or the
                x509 public key certificate.

        Returns:
            google.auth.crypt.RSAVerifier: The constructed verifier.

        Raises:
            ValueError: If the public_key can't be parsed.
        """
        raise _build_error(cls)


class RSASigner(base.Signer, base.FromServiceAccountMixin):
    """Signs messages with an RSA private key.

    Args:
        private_key (rsa.key.PrivateKey): The private key to sign with.
        key_id (str): Optional key ID used to identify this private key. This
            can be useful to associate the private key with its associated
            public key or certificate.
    """

    def __init__(self, private_key, key_id=None):
        raise _build_error(self)

    @property  # type: ignore
    @_helpers.copy_docstring(base.Signer)
    def key_id(self):
        raise _build_error(self)

    @_helpers.copy_docstring(base.Signer)
    def sign(self, message):
        raise _build_error(self)

    @classmethod
    def from_string(cls, key, key_id=None):
        """Construct an Signer instance from a private key in PEM format.

        Args:
            key (str): Private key in PEM format.
            key_id (str): An optional key id used to identify the private key.

        Returns:
            google.auth.crypt.Signer: The constructed signer.

        Raises:
            ValueError: If the key cannot be parsed as PKCS#1 or PKCS#8 in
                PEM format.
        """
        raise _build_error(cls)
