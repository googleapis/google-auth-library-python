# Copyright 2025 Google LLC
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

"""Helpers for Agent Identity credentials."""

import base64
import hashlib
import os
import re
import time

from google.auth import environment_vars
from google.auth import exceptions
from google.auth.transport import _mtls_helper

# SPIFFE trust domain patterns for Agent Identities.
_AGENT_IDENTITY_SPIFFE_TRUST_DOMAIN_PATTERNS = [
    r"^agents\.global\.org-\d+\.system\.id\.goog$",
    r"^agents\.global\.proj-\d+\.system\.id\.goog$",
]


def get_agent_identity_certificate_path():
    """Gets the certificate path from the certificate config file.

    The path to the certificate config file is read from the
    GOOGLE_API_CERTIFICATE_CONFIG environment variable. This function
    implements a retry mechanism to handle cases where the environment
    variable is set before the file is available on the filesystem.

    Returns:
        str: The path to the leaf certificate file.

    Raises:
        google.auth.exceptions.RefreshError: If the certificate config file
            or the certificate file cannot be found after retries.
    """
    import json

    cert_config_path = os.environ.get(environment_vars.GOOGLE_API_CERTIFICATE_CONFIG)
    if not cert_config_path:
        return None

    # Poll for the config file and the certificate file to be available.
    # Phase 1: Poll rapidly for 5 seconds (50 * 0.1s).
    # Phase 2: Slow down polling for the next 25 seconds (50 * 0.5s).
    for i in range(100):
        if os.path.exists(cert_config_path):
            with open(cert_config_path, "r") as f:
                cert_config = json.load(f)
                cert_path = (
                    cert_config.get("cert_configs", {})
                    .get("workload", {})
                    .get("cert_path")
                )
                if cert_path and os.path.exists(cert_path):
                    return cert_path
        if i < 50:
            time.sleep(0.1)
        else:
            time.sleep(0.5)

    raise exceptions.RefreshError(
        "Certificate config or certificate file not found after multiple retries. "
        f"If you are using Agent Engine, you can export "
        f"{environment_vars.GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES} to false to "
        "disable cert bound tokens to fall back to unbound tokens."
    )


def parse_certificate(cert_bytes):
    """Parses a PEM-encoded certificate.

    Args:
        cert_bytes (bytes): The PEM-encoded certificate bytes.

    Returns:
        cryptography.x509.Certificate: The parsed certificate object.
    """
    from cryptography import x509

    return x509.load_pem_x509_certificate(cert_bytes)


def _is_agent_identity_certificate(cert):
    """Checks if a certificate is an Agent Identity certificate.

    This is determined by checking the Subject Alternative Name (SAN) for a
    SPIFFE ID with a trust domain matching Agent Identity patterns.

    Args:
        cert (cryptography.x509.Certificate): The parsed certificate object.

    Returns:
        bool: True if the certificate is an Agent Identity certificate,
            False otherwise.
    """
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return False
    uris = ext.value.get_values_for_type(x509.UniformResourceIdentifier)

    for uri in uris:
        if uri.startswith("spiffe://"):
            spiffe_id = uri[len("spiffe://") :]
            trust_domain = spiffe_id.split("/", 1)[0]
            for pattern in _AGENT_IDENTITY_SPIFFE_TRUST_DOMAIN_PATTERNS:
                if re.match(pattern, trust_domain):
                    return True
    return False


def calculate_certificate_fingerprint(cert):
    """Calculates the base64-encoded SHA256 hash of a DER-encoded certificate.

    Args:
        cert (cryptography.x509.Certificate): The parsed certificate object.

    Returns:
        str: The base64-encoded SHA256 fingerprint.
    """
    from cryptography.hazmat.primitives import serialization

    der_cert = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(der_cert).digest()
    return base64.urlsafe_b64encode(fingerprint).rstrip(b"=").decode("utf-8")


def should_request_bound_token(cert):
    """Determines if a bound token should be requested.

    This is based on the GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES
    environment variable and whether the certificate is an agent identity cert.

    Args:
        cert (cryptography.x509.Certificate): The parsed certificate object.

    Returns:
        bool: True if a bound token should be requested, False otherwise.
    """
    is_agent_cert = _is_agent_identity_certificate(cert)
    is_opted_in = (
        os.environ.get(
            environment_vars.GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES,
            "true",
        ).lower()
        == "true"
    )
    return is_agent_cert and is_opted_in


def call_client_cert_callback():
    """Calls the client cert callback and returns the certificate and key."""
    _, cert_bytes, key_bytes, passphrase = _mtls_helper.get_client_ssl_credentials(
        generate_encrypted_key=True
    )
    return cert_bytes, key_bytes


def get_cached_cert_fingerprint(cached_cert):
    """Returns the fingerprint of the cached certificate."""
    if cached_cert:
        cert_obj = parse_certificate(cached_cert)
        cached_cert_fingerprint = calculate_certificate_fingerprint(cert_obj)
    else:
        raise ValueError("mTLS connection is not configured.")
    return cached_cert_fingerprint
