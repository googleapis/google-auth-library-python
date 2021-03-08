# Copyright 2021 Google LLC
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


import json
import os
import tempfile

from google.oauth2 import service_account
from googleapiclient import discovery
import pytest

_AUDIENCE_OIDC = "//iam.googleapis.com/projects/79992041559/locations/global/workloadIdentityPools/pool-73wslmxn/providers/oidc-73wslmxn"


@pytest.fixture
def oidc_credentials(service_account_file, http_request):
    result = service_account.IDTokenCredentials.from_service_account_file(
        service_account_file,
        target_audience=_AUDIENCE_OIDC)
    result.refresh(http_request)
    yield result


@pytest.fixture
def service_account_info(service_account_file):
    with open(service_account_file) as f:
        return json.load(f)


# Our BYOID tests involve setting up some preconditions, setting a credential file,
# and then making sure that our client libraries can work with the set credentials.
def get_project_dns(project_id, credential_data):
    fd, credfile_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'w') as credfile:
            credfile.write(json.dumps(credential_data))

        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credfile_path

        # If our setup and credential file are correct,
        # discovery.build should be able to establish these as the default credentials.
        service = discovery.build('dns', 'v1')
        request = service.projects().get(project=project_id)
        return request.execute()
    finally:
        os.remove(credfile_path)


# This test makes sure that setting an accesible credential file
# works to allow access to Google resources.
def test_file_based_byoid(oidc_credentials, service_account_info):
    fd, tmpfile_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'w') as tmpfile:
            tmpfile.write(oidc_credentials.token)

        assert get_project_dns(service_account_info["project_id"], {
            "type": "external_account",
            "audience": _AUDIENCE_OIDC,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": "https://sts.googleapis.com/v1beta/token",
            "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:generateAccessToken".format(oidc_credentials.service_account_email),
            "credential_source": {
                "file": tmpfile_path,
            },
        })
    finally:
        os.remove(tmpfile_path)
