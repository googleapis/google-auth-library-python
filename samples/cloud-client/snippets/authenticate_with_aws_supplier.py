# Copyright 2024 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# [START auth_cloud_aws_supplier]

from google.cloud import storage

from google.auth import aws
from google.auth import exceptions
import boto3


class CustomAwsSecurityCredentialsSupplier(aws.AwsSecurityCredentialsSupplier):

    def __init__(self, region):
        self._region = region

    def get_aws_security_credentials(self, context, request):
        aws_credentials = boto3.Session(region_name=self._region).get_credentials().get_frozen_credentials()

        try:
            return aws.AwsSecurityCredentials(aws_credentials.access_key, aws_credentials.secret_key, aws_credentials.token)
        except Exception as e:
            raise exceptions.RefreshError(e, retryable=True)

    def get_aws_region(self, context, request):
        return self._region


def authenticate_with_aws_supplier(project_id="your-google-cloud-project-id", aws_region="your_aws_region", audience="your_federation_audience"):
    """
    List storage buckets by authenticating with a custom AWS supplier.

    // TODO(Developer) Before running this sample,:
    //  1. Replace the project, region, and audience variables.
    //  2. Make sure you have the necessary permission to list storage buckets: "storage.buckets.list"
    """

    credentials = aws.Credentials(
        audience,
        "urn:ietf:params:aws:token-type:aws4_request",
        aws_security_credentials_supplier=CustomAwsSecurityCredentialsSupplier(aws_region),
        scopes=['https://www.googleapis.com/auth/cloud-platform']
    )

    # Construct the Storage client.
    storage_client = storage.Client(credentials=credentials, project=project_id)
    buckets = storage_client.list_buckets()
    print("Buckets:")
    for bucket in buckets:
        print(bucket.name)
    print("Listed all storage buckets.")

# [END auth_cloud_aws_supplier]
