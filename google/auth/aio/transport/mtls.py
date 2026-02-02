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
Helper functions for mTLS in asyncio.
"""

import asyncio
import contextlib
import logging
import os
import ssl
import tempfile
from typing import Optional

from google.auth import exceptions



@contextlib.contextmanager
def _create_temp_file(content: bytes):
    """Creates a temporary file with the given content.
    
    Args:
        content (bytes): The content to write to the file.
        
    Yields:
        str: The path to the temporary file.
    """
    # Create a temporary file that is readable only by the owner.
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        yield path
    finally:
        # Securely delete the file after use.
        if os.path.exists(path):
            os.remove(path)


def make_client_cert_ssl_context(
    cert_bytes: bytes, key_bytes: bytes, passphrase: Optional[bytes] = None
) -> ssl.SSLContext:
    """Creates an SSLContext with the given client certificate and key.

    This function writes the certificate and key to temporary files so that
    ssl.create_default_context can load them, as the ssl module requires
    file paths for client certificates.

    Args:
        cert_bytes (bytes): The client certificate content in PEM format.
        key_bytes (bytes): The client private key content in PEM format.
        passphrase (Optional[bytes]): The passphrase for the private key, if any.

    Returns:
        ssl.SSLContext: The configured SSL context with client certificate.
    
    Raises:
        google.auth.exceptions.TransportError: If there is an error loading the certificate.
    """
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # Write cert and key to temp files because ssl.load_cert_chain requires paths
        with _create_temp_file(cert_bytes) as cert_path:
            with _create_temp_file(key_bytes) as key_path:
                context.load_cert_chain(
                    certfile=cert_path,
                    keyfile=key_path,
                    password=passphrase
                )
        return context
    except (ssl.SSLError, OSError) as exc:
        raise exceptions.TransportError(
            "Failed to load client certificate and key for mTLS."
        ) from exc
