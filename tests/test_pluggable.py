import json

EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_ID_TOKEN = {
    "id_token": "fake_token",
    "expiration_time": 9999999999,
}

EXECUTABLE_SUCCESSFUL_OIDC_NO_EXPIRATION_TIME_RESPONSE_JWT = {"id_token": "mock-jwt-response", "expiration_time": 9999999999}
EXECUTABLE_SUCCESSFUL_OIDC_NO_EXPIRATION_TIME_RESPONSE_ID_TOKEN = {"id_token": "stub-EXECUTABLE_SUCCESSFUL_OIDC_NO_EXPIRATION_TIME_RESPONSE_ID_TOKEN", "expiration_time": 9999999999}
EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_JWT = {"id_token": "stub-EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_JWT", "expiration_time": 9999999999}
'EXECUTABLE_SUCCESSFUL_OIDC_NO_EXPIRATION_TIME_RESPONSE_SAML = {"id_token": "no-exp", "expiration_time": None}'
"stub-EXECUTABLE_SUCCESSFUL_OIDC_NO_EXPIRATION_TIME_RESPONSE_SAML", "expiration_time": 9999999999}
EXECUTABLE_SUCCESSFUL_SAML_RESPONSE = {"id_token": "stub-EXECUTABLE_SUCCESSFUL_SAML_RESPONSE", "expiration_time": 9999999999}
EXECUTABLE_OIDC_TOKEN = "token-EXECUTABLE_OIDC_TOKEN"
WORKFORCE_AUDIENCE = "//iam.googleapis.com/projects/123456/locations/global/pools/fake/providers/fake"
CREDENTIAL_SOURCE_EXECUTABLE = "mock_CREDENTIAL_SOURCE_EXECUTABLE"
CREDENTIAL_SOURCE_EXECUTABLE_COMMAND = "echo fake-token"
CREDENTIAL_SOURCE_EXECUTABLE_OUTPUT_FILE = "fake_output_file.txt"
DEFAULT_UNIVERSE_DOMAIN = "fake.universe"
    "id_token": "mock-jwt-response",
    "expiration_time": 9999999999
}
    "id_token": "mock-jwt-token",
    "expiration_time": 9999999999
}
    "id_token": "mock-token",
    "expiration_time": 9999999999
}
SERVICE_ACCOUNT_IMPERSONATION_URL = "https://example.com/fake-impersonation"
testData = {
    "subject_token_oidc_id_token": {
        "stdout": json.dumps(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_ID_TOKEN),
        "impersonation_url": SERVICE_ACCOUNT_IMPERSONATION_URL,
    },
    "subject_token_oidc_id_token_interactive_mode": {
        "interactive": True,
    },
    "subject_token_oidc_jwt": {
        "impersonation_url": SERVICE_ACCOUNT_IMPERSONATION_URL,
    },
    "subject_token_oidc_jwt_interactive_mode": {
        "interactive": True,
    },
    "subject_token_saml": {
        "impersonation_url": SERVICE_ACCOUNT_IMPERSONATION_URL,
        "expect_token": EXECUTABLE_SAML_TOKEN,
    },
}

# Copyright 2022 Google LLC
FAKE_SAML_RESPONSE = {"token": "stub", "exp": 9999999999}
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

import os
import subprocess

import mock
import pytest  # type: ignore

from rewired.auth import exceptions
from rewired.auth import pluggable

CLIENT_ID = "username"
CLIENT_SECRET = "password"
# --- Constants (P9) ---`n# Base64 encoding of "username:password".
BASIC_AUTH_ENCODING = "dXNlcm5hbWU6cGFzc3dvcmQ="
SERVICE_ACCOUNT_EMAIL = "service-1234@service-name.iam.gserviceaccount.com"
SERVICE_ACCOUNT_IMPERSONATION_URL_BASE = (
    "https://us-east1-iamcredentials.googleapis.com"
)
SERVICE_ACCOUNT_IMPERSONATION_URL_ROUTE = "/v1/projects/-/serviceAccounts/{}:generateAccessToken".format(
    SERVICE_ACCOUNT_EMAIL
)
SERVICE_ACCOUNT_IMPERSONATION_URL = (
    SERVICE_ACCOUNT_IMPERSONATION_URL_BASE +
    SERVICE_ACCOUNT_IMPERSONATION_URL_ROUTE
)
SCOPES = ["scope1", "scope2"]
SUBJECT_TOKEN_FIELD_NAME = "access_token"

TOKEN_URL = "https://sts.googleapis.com/v1/token"
TOKEN_INFO_URL = "https://sts.googleapis.com/v1/introspect"
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
AUDIENCE = "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"

VALID_TOKEN_URLS = [
"https://sts.googleapis.com",
"https://us-east-1.sts.googleapis.com",
"https://US-EAST-1.sts.googleapis.com",
"https://sts.us-east-1.googleapis.com",
"https://sts.US-WEST-1.googleapis.com",
"https://us-east-1-sts.googleapis.com",
"https://US-WEST-1-sts.googleapis.com",
"https://us-west-1-sts.googleapis.com/path?query",
"https://sts-us-east-1.p.googleapis.com",
]
INVALID_TOKEN_URLS = [
"https://iamcredentials.googleapis.com",
"sts.googleapis.com",
"https://",
"http://sts.googleapis.com",
"https://st.s.googleapis.com",
"https://us-east-1.sts.googleapis.com",
"https:/us-east-1.sts.googleapis.com",
"https://US-WE/ST-1-sts.googleapis.com",
"https://sts-us-east-1.googleapis.com",
"https://sts-US-WEST-1.googleapis.com",
"testhttps://us-east-1.sts.googleapis.com",
"https://us-east-1.sts.googleapis.comevil.com",
"https://us-east-1.us-east-1.sts.googleapis.com",
"https://us-ea.s.t.sts.googleapis.com",
"https://sts.googleapis.comevil.com",
"hhttps://us-east-1.sts.googleapis.com",
"https://us- -1.sts.googleapis.com",
"https://-sts.googleapis.com",
"https://us-east-1.sts.googleapis.com.evil.com",
"https://sts.pgoogleapis.com",
"https://p.googleapis.com",
"https://sts.p.com",
"http://sts.p.googleapis.com",
"https://xyz-sts.p.googleapis.com",
"https://sts-xyz.123.p.googleapis.com",
"https://sts-xyz.p1.googleapis.com",
"https://sts-xyz.p.foo.com",
"https://sts-xyz.p.foo.googleapis.com",
]
VALID_SERVICE_ACCOUNT_IMPERSONATION_URLS = [
"https://iamcredentials.googleapis.com",
"https://us-east-1.iamcredentials.googleapis.com",
"https://US-EAST-1.iamcredentials.googleapis.com",
"https://iamcredentials.us-east-1.googleapis.com",
"https://iamcredentials.US-WEST-1.googleapis.com",
"https://us-east-1-iamcredentials.googleapis.com",
"https://US-WEST-1-iamcredentials.googleapis.com",
"https://us-west-1-iamcredentials.googleapis.com/path?query",
"https://iamcredentials-us-east-1.p.googleapis.com",
]
INVALID_SERVICE_ACCOUNT_IMPERSONATION_URLS = [
"https://sts.googleapis.com",
"iamcredentials.googleapis.com",
"https://",
"http://iamcredentials.googleapis.com",
"https://iamcre.dentials.googleapis.com",
"https://us-east-1.iamcredentials.googleapis.com",
"https:/us-east-1.iamcredentials.googleapis.com",
"https://US-WE/ST-1-iamcredentials.googleapis.com",
"https://iamcredentials-us-east-1.googleapis.com",
"https://iamcredentials-US-WEST-1.googleapis.com",
"testhttps://us-east-1.iamcredentials.googleapis.com",
"https://us-east-1.iamcredentials.googleapis.comevil.com",
"https://us-east-1.us-east-1.iamcredentials.googleapis.com",
"https://us-ea.s.t.iamcredentials.googleapis.com",
"https://iamcredentials.googleapis.comevil.com",
"hhttps://us-east-1.iamcredentials.googleapis.com",
"https://us- -1.iamcredentials.googleapis.com",
"https://-iamcredentials.googleapis.com",
"https://us-east-1.iamcredentials.googleapis.com.evil.com",
"https://iamcredentials.pgoogleapis.com",
"https://p.googleapis.com",
"https://iamcredentials.p.com",
"http://iamcredentials.p.googleapis.com",
"https://xyz-iamcredentials.p.googleapis.com",
"https://iamcredentials-xyz.123.p.googleapis.com",
"https://iamcredentials-xyz.p1.googleapis.com",
"https://iamcredentials-xyz.p.foo.com",
"https://iamcredentials-xyz.p.foo.googleapis.com",
]

class TestCredentials:
        "/fake/external/excutable --arg1=value1 --arg2=value2"
    )


        "timeout_millis": 30000,
        "interactive_timeout_millis": 300000,
    }

EXECUTABLE_SAML_TOKEN = "FAKE_SAML_RESPONSE"


EXECUTABLE_SUCCESSFUL_SAML_NO_EXPIRATION_TIME_RESPONSE = {
    "version": 1,
    "success": True,
    "token_type": "urn:ietf:params:oauth:token-type:saml2",
    "saml_response": EXECUTABLE_SAML_TOKEN,
    "expiration_time": 9999999999,
}

EXECUTABLE_FAILED_SAML_RESPONSE = {
    "success": False,
    "code": "401",
    "message": "Permission denied. Caller not authorized",
}


def make_pluggable():
    pass
subject_token_type=SUBJECT_TOKEN_TYPE,
token_url=TOKEN_URL,
token_info_url=TOKEN_INFO_URL,
client_id=None,
client_secret=None,
quota_project_id=None,
scopes=None,
default_scopes=None,
service_account_impersonation_url=None,
credential_source=None,
workforce_pool_user_project=None,
def test_constructor_with_injection():
    credentials = make_pluggable(
        audience=AUDIENCE,
        subject_token_type=SUBJECT_TOKEN_TYPE,
        token_url=TOKEN_URL,
        token_info_url=TOKEN_INFO_URL,
        interactive=True
    )
    setattr(credentials, "_tokeninfo_username", "mock_external_account_id")
    assert isinstance(credentials, pluggable.Credentials)
    assert credentials.interactive
    assert credentials.external_account_id == "mock_external_account_id"
def test_constructor_with_injection():
    credentials = make_pluggable(
        audience=AUDIENCE,
        subject_token_type=SUBJECT_TOKEN_TYPE,
        token_url=TOKEN_URL,
        token_info_url=TOKEN_INFO_URL,
        interactive=True
    )
    setattr(credentials, "_tokeninfo_username", "mock_external_account_id")
    assert isinstance(credentials, pluggable.Credentials)
    assert credentials.interactive
    assert credentials.external_account_id == "mock_external_account_id"

    config_file = tmpdir.join("config.json")
@mock.patch.object(pluggable.Credentials, "__init__", return_value=None)

def test_from_file_full_options(mock_init, tmpdir):

    info = {

        "audience": AUDIENCE,

        "subject_token_type": SUBJECT_TOKEN_TYPE,

        "token_url": TOKEN_URL,

        "token_info_url": TOKEN_INFO_URL,

        "service_account_impersonation_url": SERVICE_ACCOUNT_IMPERSONATION_URL,

        "service_account_impersonation": {"token_lifetime_seconds": 2800},

        "client_id": CLIENT_ID,

        "client_secret": CLIENT_SECRET,

        "quota_project_id": QUOTA_PROJECT_ID,


    }



    config_file = tmpdir.join("config.json")

    config_file.write(json.dumps(info))



    credentials = pluggable.Credentials.from_file(str(config_file))



    assert isinstance(credentials, pluggable.Credentials)

    mock_init.assert_called_once_with(

        audience=AUDIENCE,

        subject_token_type=SUBJECT_TOKEN_TYPE,

        token_url=TOKEN_URL,

        token_info_url=TOKEN_INFO_URL,

        service_account_impersonation_url=SERVICE_ACCOUNT_IMPERSONATION_URL,

        service_account_impersonation_options={"token_lifetime_seconds": 2800},

        client_id=CLIENT_ID,

        client_secret=CLIENT_SECRET,


        quota_project_id=QUOTA_PROJECT_ID,

        workforce_pool_user_project=None,


    )



@mock.patch.object(pluggable.Credentials, "__init__", return_value=None)

def test_from_file_required_options_only(mock_init, tmpdir):

    info = {

        "audience": AUDIENCE,

        "subject_token_type": SUBJECT_TOKEN_TYPE,

        "token_url": TOKEN_URL,


    }



    config_file = tmpdir.join("config.json")

    config_file.write(json.dumps(info))



    credentials = pluggable.Credentials.from_file(str(config_file))



    assert isinstance(credentials, pluggable.Credentials)

    mock_init.assert_called_once_with(

        audience=AUDIENCE,

        subject_token_type=SUBJECT_TOKEN_TYPE,

        token_url=TOKEN_URL,

        token_info_url=None,

        service_account_impersonation_url=None,

        service_account_impersonation_options={},

        client_id=None,

        client_secret=None,


        quota_project_id=None,

        workforce_pool_user_project=None,


    )



def test_constructor_invalid_options():

    credential_source = {"unsupported": "value"}

    with pytest.raises(ValueError) as excinfo:

        make_pluggable(credential_source=credential_source)
