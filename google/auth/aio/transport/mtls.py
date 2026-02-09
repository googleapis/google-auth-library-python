# Copyright 2024 Google LLC
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
Helper functions for mTLS in async.
"""

import logging
from os import getenv, path

import google.auth.transport._mtls_helper

CERTIFICATE_CONFIGURATION_DEFAULT_PATH = "~/.config/gcloud/certificate_config.json"
_LOGGER = logging.getLogger(__name__)


def _check_config_path(config_path):
    """Checks for config file path. If it exists, returns the absolute path with user expansion;
    otherwise returns None.

    Args:
        config_path (str): The config file path for certificate_config.json for example

    Returns:
        str: absolute path if exists and None otherwise.
    """
    config_path = path.expanduser(config_path)
    if not path.exists(config_path):
        _LOGGER.debug("%s is not found.", config_path)
        return None
    return config_path


def has_default_client_cert_source():
    """Check if default client SSL credentials exists on the device.

    Returns:
        bool: indicating if the default client cert source exists.
    """
    if _check_config_path(CERTIFICATE_CONFIGURATION_DEFAULT_PATH) is not None:
        return True
    cert_config_path = getenv("GOOGLE_API_CERTIFICATE_CONFIG")
    if cert_config_path and _check_config_path(cert_config_path) is not None:
        return True
    return False


def get_client_ssl_credentials(
    generate_encrypted_key=False,
    certificate_config_path=None,
):
    """Returns the client side certificate, private key and passphrase.

    We look for certificates and keys with the following order of priority:
        1. Certificate and key specified by certificate_config.json.
               Currently, only X.509 workload certificates are supported.

    Args:
        generate_encrypted_key (bool): If set to True, encrypted private key
            and passphrase will be generated; otherwise, unencrypted private key
            will be generated and passphrase will be None. This option only
            affects keys obtained via context_aware_metadata.json.
        certificate_config_path (str): The certificate_config.json file path.

    Returns:
        Tuple[bool, bytes, bytes, bytes]:
            A boolean indicating if cert, key and passphrase are obtained, the
            cert bytes and key bytes both in PEM format, and passphrase bytes.

    Raises:
        google.auth.exceptions.ClientCertError: if problems occurs when getting
            the cert, key and passphrase.
    """

    # Attempt to retrieve X.509 Workload cert and key.
    cert, key = google.auth.transport._mtls_helper._get_workload_cert_and_key(
        certificate_config_path
    )
    if cert and key:
        return True, cert, key, None

    return False, None, None, None


def get_client_cert_and_key(client_cert_callback=None):
    """Returns the client side certificate and private key. The function first
    tries to get certificate and key from client_cert_callback; if the callback
    is None or doesn't provide certificate and key, the function tries application
    default SSL credentials.

    Args:
        client_cert_callback (Optional[Callable[[], (bytes, bytes)]]): An
            optional callback which returns client certificate bytes and private
            key bytes both in PEM format.

    Returns:
        Tuple[bool, bytes, bytes]:
            A boolean indicating if cert and key are obtained, the cert bytes
            and key bytes both in PEM format.

    Raises:
        google.auth.exceptions.ClientCertError: if problems occurs when getting
            the cert and key.
    """
    if client_cert_callback:
        cert, key = client_cert_callback()
        return True, cert, key

    has_cert, cert, key, _ = get_client_ssl_credentials(generate_encrypted_key=False)
    return has_cert, cert, key
