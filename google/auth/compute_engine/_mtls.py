# -*- coding: utf-8 -*-
#
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Mutual TLS for Google Compute Engine metadata server."""
import enum
import os
import ssl

import requests
from requests.adapters import HTTPAdapter

from google.auth import environment_vars

# TODO: update to use well-known paths.
_CA_CERT_PATH = "/home/neastin/mtls_mds_certificates/root.crt"
_CLIENT_COMBINED_CERT_PATH = "/home/neastin/mtls_mds_certificates/client_creds.key"


class MdsMtlsMode(enum.Enum):
    """MDS mTLS mode."""

    STRICT = "strict"
    NONE = "none"
    DEFAULT = "default"


def _parse_mds_mode():
    """Parses the GCE_METADATA_MTLS_MODE environment variable."""
    mode_str = os.environ.get(environment_vars.GCE_METADATA_MTLS_MODE, "default").lower()
    try:
        return MdsMtlsMode(mode_str)
    except ValueError:
        raise ValueError(
            "Invalid value for GCE_METADATA_MTLS_MODE. Must be one of 'strict', 'none', or 'default'."
        )


def _certs_exist():
    """Checks if the mTLS certificates exist."""
    return os.path.exists(_CA_CERT_PATH) and os.path.exists(
        _CLIENT_COMBINED_CERT_PATH
    )


class MdsMtlsAdapter(HTTPAdapter):
    """An HTTP adapter that uses mTLS for the metadata server."""

    def __init__(self, *args, **kwargs):
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.load_verify_locations(cafile=_CA_CERT_PATH)
        self.ssl_context.load_cert_chain(certfile=_CLIENT_COMBINED_CERT_PATH)
        super(MdsMtlsAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super(MdsMtlsAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super(MdsMtlsAdapter, self).proxy_manager_for(*args, **kwargs)


def create_session():
    """Creates a requests.Session configured for mTLS."""
    session = requests.Session()
    adapter = MdsMtlsAdapter()
    session.mount("https://", adapter)
    return session


def should_use_mds_mtls():
    """Determines if mTLS should be used for the metadata server."""
    mode = _parse_mds_mode()
    if mode == MdsMtlsMode.STRICT:
        if not _certs_exist():
            raise IOError("mTLS certificates not found in strict mode.")
        return True
    elif mode == MdsMtlsMode.NONE:
        return False
    else:  # Default mode
        return _certs_exist()