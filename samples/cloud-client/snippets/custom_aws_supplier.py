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
from botocore.exceptions import NoRegionError
from dotenv import load_dotenv
from google.auth.aws import AwsClient, AwsSecurityCredentials
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import AuthorizedSession

load_dotenv()


class CustomAwsSupplier:
    """Custom AWS Security Credentials Supplier.

    This implementation resolves AWS credentials using the default provider
    chain from the AWS SDK for Python (Boto3). This allows fetching credentials
    from environment variables, shared credential files (~/.aws/credentials),
    or IAM roles for service accounts (IRSA) in EKS, etc.
    """

    def __init__(self):
        """Initializes the AWS credential provider."""
        # Boto3 session handles caching and proactive refreshing internally.
        self.session = boto3.Session()
        self._region = None

    def get_aws_region(self, context) -> str:
        """Returns the AWS region.

        This is required for signing the AWS request. It resolves the region
        automatically by using the default AWS region provider chain from Boto3.

        Args:
            context: The context object, not used in this implementation.

        Returns:
            The AWS region as a string.

        Raises:
            GoogleAuthError: If the AWS region cannot be resolved.
        """
        if self._region:
            return self._region

        try:
            self._region = self.session.region_name
            if not self._region:
                # If region is not configured, try to get it from a client.
                sts_client = self.session.client("sts")
                self._region = sts_client.meta.region
        except NoRegionError:
            raise GoogleAuthError(
                "CustomAwsSupplier: Unable to resolve AWS region. Please set the "
                "AWS_REGION environment variable or configure it in your "
                "~/.aws/config file."
            )

        return self._region

    def get_aws_security_credentials(self, context) -> AwsSecurityCredentials:
        """Retrieves AWS security credentials using Boto3's default provider chain.

        Args:
            context: The context object, not used in this implementation.

        Returns:
            An AwsSecurityCredentials object containing the AWS credentials.

        Raises:
            GoogleAuthError: If AWS credentials cannot be resolved.
        """
        # Get credentials from the session. Boto3 handles caching and refreshing.
        aws_credentials = self.session.get_credentials()
        if not aws_credentials:
            raise GoogleAuthError(
                "Unable to resolve AWS credentials from the provider chain. "
                "Ensure your AWS CLI is configured, or AWS environment variables "
                "(like AWS_ACCESS_KEY_ID) are set."
            )

        # Map the Boto3 format to the google-auth-library format.
        return AwsSecurityCredentials(
            access_key_id=aws_credentials.access_key,
            secret_access_key=aws_credentials.secret_key,
            token=aws_credentials.token,
        )


def main():
    """Main function to demonstrate the custom AWS supplier.

    TODO(Developer):
    1. Before running this sample, set up your environment variables. You can do
       this by creating a .env file in the same directory as this script and
       populating it with the following variables:
       - GCP_WORKLOAD_AUDIENCE: The audience for the GCP workload identity pool.
       - GCP_SERVICE_ACCOUNT_IMPERSONATION_URL: The URL for service account impersonation.
       - GCS_BUCKET_NAME: The name of the GCS bucket to access.
    2. Ensure your AWS credentials are configured correctly so that boto3 can
       resolve them. You can do this by setting the AWS_ACCESS_KEY_ID,
       AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN environment variables, or by
       configuring the ~/.aws/credentials and ~/.aws/config files.
    """
    gcp_audience = os.getenv("GCP_WORKLOAD_AUDIENCE")
    sa_impersonation_url = os.getenv("GCP_SERVICE_ACCOUNT_IMPERSONATION_URL")
    gcs_bucket_name = os.getenv("GCS_BUCKET_NAME")

    if not all([gcp_audience, sa_impersonation_url, gcs_bucket_name]):
        raise GoogleAuthError(
            "Missing required environment variables. Please check your .env file "
            "or environment settings. Required: GCP_WORKLOAD_AUDIENCE, "
            "GCP_SERVICE_ACCOUNT_IMPERSONATION_URL, GCS_BUCKET_NAME"
        )

    # 1. Instantiate the custom supplier.
    custom_supplier = CustomAwsSupplier()

    # 2. Configure the AwsClient options.
    client_options = {
        "audience": gcp_audience,
        "subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
        "service_account_impersonation_url": sa_impersonation_url,
        "aws_security_credentials_supplier": custom_supplier,
    }

    # 3. Create the auth client.
    client = AwsClient(**client_options)

    # 4. Construct the URL for the Cloud Storage JSON API.
    bucket_url = f"https://storage.googleapis.com/storage/v1/b/{gcs_bucket_name}"
    print(f"[Test] Getting metadata for bucket: {gcs_bucket_name}...")
    print(f"[Test] Request URL: {bucket_url}")

    # 5. Use the client to make an authenticated request.
    authed_session = AuthorizedSession(client)
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
