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
import logging
import os
import re
import time
from urllib.parse import urlparse

from google.auth import environment_vars
from google.auth import exceptions


_LOGGER = logging.getLogger(__name__)

# SPIFFE trust domain patterns for Agent Identities.
_AGENT_IDENTITY_SPIFFE_TRUST_DOMAIN_PATTERNS = [
    r"^agents\.global\.org-\d+\.system\.id\.goog$",
    r"^agents\.global\.proj-\d+\.system\.id\.goog$",
]

# Constants for polling the certificate file.
_FAST_POLL_CYCLES = 50
_FAST_POLL_INTERVAL = 0.1  # 100ms
_SLOW_POLL_INTERVAL = 0.5  # 500ms
_TOTAL_TIMEOUT = 30  # seconds

# Calculate the number of slow poll cycles based on the total timeout.
_SLOW_POLL_CYCLES = int(
    (_TOTAL_TIMEOUT - (_FAST_POLL_CYCLES * _FAST_POLL_INTERVAL)) / _SLOW_POLL_INTERVAL
)

_POLLING_INTERVALS = ([_FAST_POLL_INTERVAL] * _FAST_POLL_CYCLES) + (
    [_SLOW_POLL_INTERVAL] * _SLOW_POLL_CYCLES
)


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

    has_logged_warning = False

    for interval in _POLLING_INTERVALS:
        try:
            with open(cert_config_path, "r") as f:
                cert_config = json.load(f)
                cert_path = (
                    cert_config.get("cert_configs", {})
                    .get("workload", {})
                    .get("cert_path")
                )
                if cert_path and os.path.exists(cert_path):
                    return cert_path
        except (IOError, ValueError, KeyError):
            if not has_logged_warning:
                _LOGGER.warning(
                    "Certificate config file not found at %s (from %s environment "
                    "variable). Retrying for up to %s seconds.",
                    cert_config_path,
                    environment_vars.GOOGLE_API_CERTIFICATE_CONFIG,
                    _TOTAL_TIMEOUT,
                )
                has_logged_warning = True
            pass

        time.sleep(interval)

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
    try:
        from cryptography import x509
    except ImportError:
        raise ImportError(
            "The cryptography library is required for certificate-based authentication."
            "Please install it with `pip install google-auth[cryptography]`."
        )

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
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
    except ImportError:
        raise ImportError(
            "The cryptography library is required for certificate-based authentication."
            "Please install it with `pip install google-auth[cryptography]`."
        )

    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return False
    uris = ext.value.get_values_for_type(x509.UniformResourceIdentifier)

    for uri in uris:
        parsed_uri = urlparse(uri)
        if parsed_uri.scheme == "spiffe":
            trust_domain = parsed_uri.netloc
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
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        raise ImportError(
            "The cryptography library is required for certificate-based authentication."
            "Please install it with `pip install google-auth[cryptography]`."
        )

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
