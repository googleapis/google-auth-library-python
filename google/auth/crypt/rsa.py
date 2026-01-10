# Copyright 2017 Google LLC
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
RSA cryptography signer and verifier.

This file provides a shared wrapper, that defers to _python_rsa or _cryptography_rsa
for implmentations using different third party libraries
"""

from google.auth.crypt import base
from google.auth import _helpers
from google.auth.exceptions import MissingOptionalDependencyError

try:
    # Attempt import of module that requires optional `cryptography` dependency
    from google.auth.crypt import _cryptography_rsa
except ImportError:  # pragma: NO COVER
    _cryptography_rsa = None

try:
    # Attempt import of module that requires optional (deprecated) `rsa` dependency
    from google.auth.crypt import _python_rsa
except ImportError:  # pragma: NO COVER
    _python_rsa = None

RSA_NOTE = "(Note: 'rsa' is also supported for legacy compatibility but is deprecated)"


class RSAVerifier(base.Verifier):
    """Verifies RSA cryptographic signatures using public keys.

    Requires installation of `cryptography` optional dependency.

    .. deprecated::
        The `rsa` library has been archived. Please migrate to
        `cryptography` for public keys.

    Args:
        public_key (Union[rsa.key.PublicKey, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey]):
            The public key used to verify signatures.
    Raises:
        ImportError: if neither `cryptograhy` or `rsa` is installed
        InvalidValue: if an unrecognized public key is provided
    """

    def __init__(self, public_key):
        module_str = public_key.__class__.__module__
        if "rsa.key" in module_str:
            impl_lib = _python_rsa
        elif "cryptography." in module_str:
            impl_lib = _cryptography_rsa
        else:
            raise InvalidValue(f"unrecognized public key type: {public_key}")
        if impl_lib is None:
            raise MissingOptionalDependencyError.create(self, "cryptography", RSA_NOTE)
        else:
            self._impl = impl_lib.RSAVerifier(public_key)

    @_helpers.copy_docstring(base.Verifier)
    def verify(self, message, signature):
        return self._impl.verify(message, signature)

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
            ImportError: if neither `cryptograhy` or `rsa` is installe
        """
        if _cryptography_rsa:
            return _cryptography_rsa.RSAVerifier.from_string(public_key)
        elif _python_rsa:
            return _python_rsa.RSAVerifier.from_string(public_key)
        else:
            raise MissingOptionalDependencyError.create(cls, "cryptography", RSA_NOTE)


class RSASigner(base.Signer, base.FromServiceAccountMixin):
    """Signs messages with an RSA private key.

    Requires installation of `cryptography` optional dependency.

    .. deprecated::
        The `rsa` library has been archived. Please migrate to
        `cryptography` for public keys.

    Args:
        private_key (Union[rsa.key.PrivateKey, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey]):
            The private key to sign with.
        key_id (str): Optional key ID used to identify this private key. This
            can be useful to associate the private key with its associated
            public key or certificate.

    Raises:
        ImportError: if neither `cryptograhy` or `rsa` is installed
        InvalidValue: if an unrecognized public key is provided
    """

    def __init__(self, private_key, key_id=None):
        module_str = private_key.__class__.__module__
        if "rsa.key" in module_str:
            impl_lib = _python_rsa
        elif "cryptography." in module_str:
            impl_lib = _cryptography_rsa
        else:
            raise InvalidValue(f"unrecognized private key type: {pivate_key}")
        if impl_lib is None:
            raise MissingOptionalDependencyError.create(self, "cryptography", RSA_NOTE)
        else:
            self._impl = impl_lib.RSASigner(private_key, key_id=key_id)

    @property  # type: ignore
    @_helpers.copy_docstring(base.Signer)
    def key_id(self):
        return self._impl.key_id

    @_helpers.copy_docstring(base.Signer)
    def sign(self, message):
        return self._impl.sign(message)

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
            ImportError: if neither `cryptograhy` or `rsa` is installe
        """
        if _cryptography_rsa:
            return _cryptography_rsa.RSASigner.from_string(key, key_id=key_id)
        elif _python_rsa:
            return _python_rsa.RSASigner.from_string(key, key_id=key_id)
        else:
            raise MissingOptionalDependencyError.create(cls, "cryptography", RSA_NOTE)