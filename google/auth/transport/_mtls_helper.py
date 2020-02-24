# Copyright 2016 Google LLC
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

"""Helper functions for getting mTLS cert and key, for internal use only."""

import json
import logging
from os import path
import subprocess

CONTEXT_AWARE_METADATA_PATH = "~/.secureConnect/context_aware_metadata.json"
_CERT_PROVIDER_COMMAND = "cert_provider_command"
_CERTIFICATE_SURFFIX = b"-----END CERTIFICATE-----\n"

_LOGGER = logging.getLogger(__name__)


def read_metadata_file(metadata_path):
    """Function to load context aware metadata from the given path.

    Args:
        metadata_path (str): context aware metadata path.

    Returns:
        Dict[str]:
            The metadata. If metadata reading or parsing fails, return None.
    """
    metadata_path = path.expanduser(metadata_path)
    if not path.exists(metadata_path):
        _LOGGER.debug("%s is not found, skip client SSL authentication.", metadata_path)
        return None

    with open(metadata_path) as f:
        try:
            metadata = json.load(f)
        except Exception as e:
            _LOGGER.debug(
                "Failed to decode context_aware_metadata.json with error: %s", str(e)
            )
            return None

    return metadata


def get_client_ssl_credentials(metadata_json, platform):
    """Function to get mTLS client side cert and key.

    Args:
        metadata_json (Dict[str]): metadata JSON file which contains the cert
            provider command.
        platform (str): The OS.

    Returns:
        Tuple[bool, bytes, bytes, bytes, bytes]:
            The tuple contains the following in order:
            (1) boolean to show if client cert and key is obtained successfully
            (2) client certificate in PEM forma if successful, otherwise None
            (3) client key in PEM format if successful, otherwise None
            (4) stdout from cert provider command execution
            (5) stderr from cert provider command execution
    """

    # Check the system. For now only Linux is supported.
    if not platform.startswith("linux"):
        _LOGGER.debug("mTLS for platform: %s is not supported.", platform)
        return False, None, None, None, None

    # Execute the cert provider command in the metadata json file.
    if _CERT_PROVIDER_COMMAND not in metadata_json:
        _LOGGER.debug("cert_provider_command missing, skip client SSL authentication")
        return False, None, None, None, None
    try:
        command = metadata_json[_CERT_PROVIDER_COMMAND]
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()
    except OSError as e:
        _LOGGER.debug("Failed to run cert provider command with error: %s", str(e))
        return False, None, None, None, None

    # Check cert provider command execution error.
    if stderr != b"":
        _LOGGER.debug("Cert provider command failed with error: %s", stderr)
        return False, None, None, stdout, stderr

    # Parse stdout, it should be a cert followed by a key, both in PEM format.
    cert_end = stdout.find(_CERTIFICATE_SURFFIX)
    if cert_end == -1:
        _LOGGER.debug("Client SSL certificate is missing")
        return False, None, None, stdout, stderr
    private_key_start = cert_end + len(_CERTIFICATE_SURFFIX)
    if private_key_start >= len(stdout):
        _LOGGER.debug("Client SSL private key is missing")
        return False, None, None, stdout, stderr
    return True, stdout[0:private_key_start], stdout[private_key_start:], stdout, stderr
