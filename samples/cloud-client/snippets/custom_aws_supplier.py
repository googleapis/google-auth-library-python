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

# [START auth_cloud_aws_supplier]

import json
import os
import sys
from typing import Optional

import boto3
from dotenv import load_dotenv

from google.auth import aws
from google.auth import exceptions
from google.cloud import storage

load_dotenv()


class CustomAwsSupplier(aws.AwsSecurityCredentialsSupplier):
    """Custom AWS Security Credentials Supplier."""

    def __init__(self, region=None):
        """Initializes the Boto3 session, prioritizing environment variables for region.

        Args:
            region Optional[str]: The AWS region name. If None, it will be
                sourced from environment variables or Boto3's default discovery.
        """

        # Explicitly read the region from the environment first. This ensures that
        # a value from a .env file is picked up reliably for local testing.
        self._region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")

        # If region is None, Boto3's discovery chain will be used when needed.
        self.session = boto3.Session(region_name=self._region)
        self._cached_region = None

        print(f"[INFO] CustomAwsSupplier initialized. Region: {self._region}")

    def get_aws_region(self, context, request) -> str:
        """Returns the AWS region using Boto3's default provider chain.
   
        Args:
            context (google.auth.transport.requests.Request): The context.
            request Optional[google.auth.transport.Request]: The request.
    
        Returns:
            str: The AWS region name.
        """

        if self._cached_region:
            return self._cached_region

        # Accessing region_name will use the value from the constructor if provided,
        # otherwise it triggers Boto3's lazy-loading discovery (e.g., metadata service).
        self._cached_region = self.session.region_name

        if not self._cached_region:
            print("[ERROR] Boto3 was unable to resolve an AWS region.", file=sys.stderr)
            raise exceptions.GoogleAuthError("Boto3 was unable to resolve an AWS region.")

        print(f"[INFO] Boto3 resolved AWS Region: {self._cached_region}")
        return self._cached_region

    def get_aws_security_credentials(self, context, request=None) -> aws.AwsSecurityCredentials:
        """Retrieves AWS security credentials using Boto3's default provider chain.
    
        Args:
            context (google.auth.transport.requests.Request): The context.
            request Optional[google.auth.transport.Request]: The request.
    
        Returns:
            aws.AwsSecurityCredentials: The AWS security credentials.
        """

        aws_credentials = self.session.get_credentials()
        if not aws_credentials:
            print("[ERROR] Unable to resolve AWS credentials.", file=sys.stderr)
            raise exceptions.GoogleAuthError("Unable to resolve AWS credentials from the provider chain.")

        print(f"[INFO] Resolved AWS Access Key ID: {aws_credentials.access_key}")

        return aws.AwsSecurityCredentials(
            access_key_id=aws_credentials.access_key,
            secret_access_key=aws_credentials.secret_key,
            session_token=aws_credentials.token,
        )


def authenticate_with_aws_supplier(project_id, aws_region, audience, service_account_impersonation_url=None):
    """
    List storage buckets by authenticating with a custom AWS supplier.
   
    Args:
        project_id (str): The Google Cloud project ID.
        aws_region Optional[str]: The AWS region name.
        audience (str): The audience for the OIDC token.
            service_account_impersonation_url Optional[str]: The URL for service account
            impersonation.
    """

    custom_supplier = CustomAwsSupplier(region=aws_region)

    credentials = aws.Credentials(
        audience=audience,
        subject_token_type="urn:ietf:params:aws:token-type:aws4_request",
        service_account_impersonation_url=service_account_impersonation_url,
        aws_security_credentials_supplier=custom_supplier,
        scopes=['https://www.googleapis.com/auth/cloud-platform'],
    )

    # Construct the Storage client.
    storage_client = storage.Client(credentials=credentials, project=project_id)
    buckets = storage_client.list_buckets()
    print("Buckets:")
    for bucket in buckets:
        print(bucket.name)
    print("Listed all storage buckets.")
# [END auth_cloud_aws_supplier]
