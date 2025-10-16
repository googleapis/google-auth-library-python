# Copyright 2025 Google LLC
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
import requests

import boto3
from dotenv import load_dotenv

from google.auth.aws import Credentials as AwsCredentials
from google.auth.aws import AwsSecurityCredentials, AwsSecurityCredentialsSupplier
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import AuthorizedSession

load_dotenv()


class CustomAwsSupplier(AwsSecurityCredentialsSupplier):
    """Custom AWS Security Credentials Supplier.

    This implementation resolves AWS credentials and region using the default
    provider chain from the AWS SDK for Python (Boto3). This allows fetching
    credentials from environment variables, shared credential files, or IAM roles.
    """

    def __init__(self):
        """Initializes the Boto3 session, which represents the default provider chain."""
        self.session = boto3.Session()
        self._cached_region = None

    def get_aws_region(self, context, request=None) -> str:
        """Returns the AWS region using the default Boto3 provider chain."""
        if self._cached_region:
            return self._cached_region

        # By creating a client from the session, Boto3 will use its full
        # default region provider chain to resolve the region. This is more
        # reliable than session.region_name alone.
        sts_client = self.session.client("sts")
        self._cached_region = sts_client.meta.region_name

        if not self._cached_region:
            raise GoogleAuthError(
                "CustomAwsSupplier: Unable to resolve AWS region. Please set the "
                "AWS_REGION environment variable, configure it in ~/.aws/config, or "
                "ensure the EC2 metadata service is accessible."
            )

        return self._cached_region

    def get_aws_security_credentials(self, context, request=None) -> AwsSecurityCredentials:
        """Retrieves AWS security credentials using Boto3's default provider chain."""
        # The Boto3 session will automatically find and refresh credentials
        # from the environment (EC2 role, env vars, etc.)
        aws_credentials = self.session.get_credentials()
        if not aws_credentials:
            raise GoogleAuthError(
                "Unable to resolve AWS credentials from the provider chain."
            )

        # Boto3 provides a read-only view, so we access the values directly.
        return AwsSecurityCredentials(
            access_key_id=aws_credentials.access_key,
            secret_access_key=aws_credentials.secret_key,
            session_token=aws_credentials.token,
        )


def main():
    """Main function to demonstrate the custom AWS supplier."""
    gcp_audience = os.getenv("GCP_WORKLOAD_AUDIENCE")
    sa_impersonation_url = os.getenv("GCP_SERVICE_ACCOUNT_IMPERSONATION_URL")
    gcs_bucket_name = os.getenv("GCS_BUCKET_NAME")

    if not all([gcp_audience, sa_impersonation_url, gcs_bucket_name]):
        raise GoogleAuthError(
            "Missing required environment variables. Please check your .env file "
            "or environment settings."
        )

    # 1. Instantiate the custom supplier.
    custom_supplier = CustomAwsSupplier()

    print(f"[Debug] Using audience: {gcp_audience}")

    # 2. Create the AWS credentials object, passing it the custom supplier.
    credentials = AwsCredentials(
        audience=gcp_audience,
        subject_token_type="urn:ietf:params:aws:token-type:aws4_request",
        service_account_impersonation_url=sa_impersonation_url,
        aws_security_credentials_supplier=custom_supplier,
        default_scopes=['https://www.googleapis.com/auth/cloud-platform'],
    )

    # 3. Construct the URL for the Cloud Storage JSON API.
    bucket_url = f"https://storage.googleapis.com/storage/v1/b/{gcs_bucket_name}"
    print(f"[Test] Getting metadata for bucket: {gcs_bucket_name}...")
    print(f"[Test] Request URL: {bucket_url}")

    # 4. Use the credentials to make an authenticated request.
    authed_session = AuthorizedSession(credentials)
    try:
        res = authed_session.get(bucket_url)
        res.raise_for_status()
        print("\n--- SUCCESS! ---")
        print("Successfully authenticated and retrieved bucket data:")
        print(json.dumps(res.json(), indent=2))
    except requests.exceptions.RequestException as e:
        print("\n--- FAILED ---")
        print(f"Request failed: {e}")
        if e.response:
            print(f"Response: {e.response.text}")
        exit(1)
    except GoogleAuthError as e:
        print("\n--- FAILED ---")
        print(f"Authentication or request failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
