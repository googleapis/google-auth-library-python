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
from tempfile import NamedTemporaryFile

import sys
import google.auth
from google.oauth2 import service_account
import pytest

_AUDIENCE_OIDC = "//iam.googleapis.com/projects/79992041559/locations/global/workloadIdentityPools/pool-73wslmxn/providers/oidc-73wslmxn"


def dns_access_direct(request, project_id):
    # First, get the default credentials.
    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        request=request,
    )

    # Apply the default credentials to the headers to make the request.
    headers = {}
    credentials.apply(headers)
    response = request(
        url="https://dns.googleapis.com/dns/v1/projects/{}".format(project_id),
        headers=headers,
    )

    if response.status == 200:
        return response.data


def dns_access_client_library(request, project_id):
    service = discovery.build("dns", "v1")
    request = service.projects().get(project=project_id)
    return request.execute()


dns_access_funcs = [dns_access_direct]
try:
    from googleapiclient import discovery

    dns_access_funcs.append(dns_access_client_library)
except ImportError as e:
    if sys.version_info[0] == 3:
        raise e


@pytest.fixture(params=dns_access_funcs)
def dns_access(request, http_request):
    def wrapper(project_id):
        return request.param(http_request, project_id)

    yield wrapper


@pytest.fixture
def oidc_credentials(service_account_file, http_request):
    result = service_account.IDTokenCredentials.from_service_account_file(
        service_account_file, target_audience=_AUDIENCE_OIDC
    )
    result.refresh(http_request)
    yield result


@pytest.fixture
def service_account_info(service_account_file):
    with open(service_account_file) as f:
        yield json.load(f)


# Our BYOID tests involve setting up some preconditions, setting a credential file,
# and then making sure that our client libraries can work with the set credentials.
def get_project_dns(dns_access, project_id, credential_data):
    with NamedTemporaryFile() as credfile:
        credfile.write(json.dumps(credential_data).encode("utf-8"))
        credfile.flush()
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credfile.name

        # If our setup and credential file are correct,
        # discovery.build should be able to establish these as the default credentials.
        return dns_access(project_id)


# This test makes sure that setting an accesible credential file
# works to allow access to Google resources.
def test_file_based_byoid(oidc_credentials, service_account_info, dns_access):
    with NamedTemporaryFile() as tmpfile:
        tmpfile.write(oidc_credentials.token.encode("utf-8"))
        tmpfile.flush()

        assert get_project_dns(
            dns_access,
            service_account_info["project_id"],
            {
                "type": "external_account",
                "audience": _AUDIENCE_OIDC,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "token_url": "https://sts.googleapis.com/v1beta/token",
                "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:generateAccessToken".format(
                    oidc_credentials.service_account_email
                ),
                "credential_source": {
                    "file": tmpfile.name,
                },
            },
        )
