# Copyright 2023 Google LLC
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

""" We use x-goog-api-client header to report metrics. This module provides
the constants and helper methods to construct x-goog-api-client header.
"""

import platform

from google.auth import version


API_CLIENT_HEADER = "x-goog-api-client"

# Auth request type
REQUEST_TYPE_ACCESS_TOKEN = "auth-request-type/at"
REQUEST_TYPE_ID_TOKEN = "auth-request-type/it"
REQUEST_TYPE_MDS_PING = "auth-request-type/mds"
REQUEST_TYPE_REAUTH_START = "auth-request-type/re-start"
REQUEST_TYPE_REAUTH_CONTINUE = "auth-request-type/re-cont"

# Credential type
CRED_TYPE_USER = "cred-type/u"
CRED_TYPE_SA_ASSERTION = "cred-type/sa"
CRED_TYPE_SA_JWT = "cred-type/jwt"
CRED_TYPE_SA_MDS = "cred-type/mds"
CRED_TYPE_SA_IMPERSONATE = "cred-type/imp"

# Versions
AUTH_LIB_VERSION = "auth/" + version.__version__
PYTHON_VERSION = "gl-python/" + platform.python_version()

# Token request metric header values

# Example: "gl-python/3.7 auth/1.1 auth-request-type/at cred-type/mds"
TOKEN_REQUEST_ACCESS_TOKEN_MDS = "{} {} {} {}".format(
    PYTHON_VERSION, AUTH_LIB_VERSION, REQUEST_TYPE_ACCESS_TOKEN, CRED_TYPE_SA_MDS
)
# Example: "gl-python/3.7 auth/1.1 auth-request-type/it cred-type/mds"
TOKEN_REQUEST_ID_TOKEN__MDS = "{} {} {} {}".format(
    PYTHON_VERSION, AUTH_LIB_VERSION, REQUEST_TYPE_ID_TOKEN, CRED_TYPE_SA_MDS
)
# Example: "gl-python/3.7 auth/1.1 auth-request-type/at cred-type/imp"
TOKEN_REQUEST_ACCESS_TOKEN_IMPERSONATE = "{} {} {} {}".format(
    PYTHON_VERSION,
    AUTH_LIB_VERSION,
    REQUEST_TYPE_ACCESS_TOKEN,
    CRED_TYPE_SA_IMPERSONATE,
)
# Example: "gl-python/3.7 auth/1.1 auth-request-type/it cred-type/imp"
TOKEN_REQUEST_ID_TOKEN_IMPERSONATE = "{} {} {} {}".format(
    PYTHON_VERSION, AUTH_LIB_VERSION, REQUEST_TYPE_ID_TOKEN, CRED_TYPE_SA_IMPERSONATE
)
# Example: "gl-python/3.7 auth/1.1 auth-request-type/at cred-type/sa"
TOKEN_REQUEST_ACCESS_ASSERTION = "{} {} {} {}".format(
    PYTHON_VERSION, AUTH_LIB_VERSION, REQUEST_TYPE_ACCESS_TOKEN, CRED_TYPE_SA_ASSERTION
)
# Example: "gl-python/3.7 auth/1.1 auth-request-type/it cred-type/sa"
TOKEN_REQUEST_ID_TOKEN_ASSERTION = "{} {} {} {}".format(
    PYTHON_VERSION, AUTH_LIB_VERSION, REQUEST_TYPE_ID_TOKEN, CRED_TYPE_SA_ASSERTION
)
# Example: "gl-python/3.7 auth/1.1 cred-type/u"
TOKEN_REQUEST_USER = "{} {} {}".format(PYTHON_VERSION, AUTH_LIB_VERSION, CRED_TYPE_USER)

# Miscellenous metrics

# Example: "gl-python/3.7 auth/1.1 auth-request-type/mds"
MDS_PING = "{} {} {}".format(PYTHON_VERSION, AUTH_LIB_VERSION, REQUEST_TYPE_MDS_PING)
# Example: "gl-python/3.7 auth/1.1 auth-request-type/re-start"
REAUTH_START = "{} {} {}".format(
    PYTHON_VERSION, AUTH_LIB_VERSION, REQUEST_TYPE_REAUTH_START
)
# Example: "gl-python/3.7 auth/1.1 cred-type/re-cont"
REAUTH_CONTINUE = "{} {} {}".format(
    PYTHON_VERSION, AUTH_LIB_VERSION, REQUEST_TYPE_REAUTH_CONTINUE
)


def add_metric_header(headers, value):
    """Add x-goog-api-client header with the given value.

    If the value is None, do nothing. If headers already has a
    x-goog-api-client header, append the value to the existing
    x-goog-api-client header. Otherwise add a new x-goog-api-client header
    with the given value.
    """
    if not value:
        return
    if API_CLIENT_HEADER not in headers:
        headers[API_CLIENT_HEADER] = value
    else:
        headers[API_CLIENT_HEADER] += " " + value
