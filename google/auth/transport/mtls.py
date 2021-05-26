# Copyright 2020 Google LLC
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

"""Utilites for mutual TLS."""

import os

from google.auth import environment_vars
from google.auth import exceptions
from google.auth.transport import _mtls_helper


def has_default_client_cert_source():
    """Check if default client SSL credentials exists on the device.

    Returns:
        bool: indicating if the default client cert source exists.
    """
    metadata_path = _mtls_helper._check_dca_metadata_path(
        _mtls_helper.CONTEXT_AWARE_METADATA_PATH
    )
    return metadata_path is not None


def default_client_cert_source():
    """Get a callback which returns the default client SSL credentials.

    Returns:
        Callable[[], [bytes, bytes]]: A callback which returns the default
            client certificate bytes and private key bytes, both in PEM format.

    Raises:
        google.auth.exceptions.DefaultClientCertSourceError: If the default
            client SSL credentials don't exist or are malformed.
    """
    if not has_default_client_cert_source():
        raise exceptions.MutualTLSChannelError(
            "Default client cert source doesn't exist"
        )

    def callback():
        try:
            _, cert_bytes, key_bytes = _mtls_helper.get_client_cert_and_key()
        except (OSError, RuntimeError, ValueError) as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(caught_exc)
            raise new_exc from caught_exc

        return cert_bytes, key_bytes

    return callback


def default_client_encrypted_cert_source(cert_path, key_path):
    """Get a callback which returns the default encrpyted client SSL credentials.

    Args:
        cert_path (str): The cert file path. The default client certificate will
            be written to this file when the returned callback is called.
        key_path (str): The key file path. The default encrypted client key will
            be written to this file when the returned callback is called.

    Returns:
        Callable[[], [str, str, bytes]]: A callback which generates the default
            client certificate, encrpyted private key and passphrase. It writes
            the certificate and private key into the cert_path and key_path, and
            returns the cert_path, key_path and passphrase bytes.

    Raises:
        google.auth.exceptions.DefaultClientCertSourceError: If any problem
            occurs when loading or saving the client certificate and key.
    """
    if not has_default_client_cert_source():
        raise exceptions.MutualTLSChannelError(
            "Default client encrypted cert source doesn't exist"
        )

    def callback():
        try:
            (
                _,
                cert_bytes,
                key_bytes,
                passphrase_bytes,
            ) = _mtls_helper.get_client_ssl_credentials(generate_encrypted_key=True)
            with open(cert_path, "wb") as cert_file:
                cert_file.write(cert_bytes)
            with open(key_path, "wb") as key_file:
                key_file.write(key_bytes)
        except (exceptions.ClientCertError, OSError) as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(caught_exc)
            raise new_exc from caught_exc

        return cert_path, key_path, passphrase_bytes

    return callback


def _load_pkcs11_private_key(key_url):
    """Get the key object from HSM with the given key_url.

    Args:
        key_url (bytes): key_url must have b"engine:<engine_id>:<key_id>" format.
            For instance, if engine id is "pkcs11", and key id is
            "pkcs11:token=token1;object=label1;pin-value=mypin", then the key_url
            is b"engine:pkcs11:pkcs11:token=token1;object=label1;pin-value=mypin".
    """
    pkcs11_so_path = os.getnenv(environment_vars.PKCS11_SO_PATH, None)
    if not pkcs11_so_path:
        raise exceptions.MutualTLSChannelError(
            "GOOGLE_AUTH_PKCS11_SO_PATH is required for PKCS#11 support."
        )

    pkcs11_module_path = os.getnenv(environment_vars.PKCS11_MODULE_PATH, None)
    if not pkcs11_module_path:
        raise exceptions.MutualTLSChannelError(
            "GOOGLE_AUTH_PKCS11_MODULE_PATH is required for PKCS#11 support."
        )

    from OpenSSL._util import ffi as _ffi, lib as _lib

    null = _ffi.NULL

    # key_url has b"engine:<engine_id>:<key_id>" format. Split it into 3 parts.
    parts = key_url.decode().split(":", 2)
    if parts[0] != "engine" or len(parts) < 3:
        raise exceptions.MutualTLSChannelError("invalid key format")
    engine_id = parts[1]
    key_id = parts[2]

    _lib.ENGINE_load_builtin_engines()
    e = _lib.ENGINE_by_id(b"dynamic")
    if not e:
        raise exceptions.MutualTLSChannelError("failed to load dynamic engine")
    if not _lib.ENGINE_ctrl_cmd_string(e, b"ID", engine_id.encode(), 0):
        raise exceptions.MutualTLSChannelError("failed to set engine ID")
    if not _lib.ENGINE_ctrl_cmd_string(e, b"SO_PATH", pkcs11_so_path.encode(), 0):
        raise exceptions.MutualTLSChannelError("failed to set SO_PATH")
    if not _lib.ENGINE_ctrl_cmd_string(e, b"LOAD", null, 0):
        raise exceptions.MutualTLSChannelError("cannot LOAD")
    if not _lib.ENGINE_ctrl_cmd_string(
        e, b"MODULE_PATH", pkcs11_module_path.encode(), 0
    ):
        raise exceptions.MutualTLSChannelError("failed to set MODULE_PATH")
    if not _lib.ENGINE_init(e):
        raise exceptions.MutualTLSChannelError("failed to init engine")
    key = _lib.ENGINE_load_private_key(e, key_id.encode(), null, null)
    if not key:
        raise exceptions.MutualTLSChannelError("failed to load private key: " + key_id)

    return key
