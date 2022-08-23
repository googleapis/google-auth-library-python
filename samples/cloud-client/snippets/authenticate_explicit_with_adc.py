# Copyright 2022 Google Inc.
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

# [START auth_cloud_explicit_adc]

from google.cloud import compute_v1
from google.cloud import storage

import google.oauth2.credentials
import google.auth


def authenticate_explicit_with_adc():
    """
    List storage buckets by authenticating with ADC.

    // TODO(Developer):
    //  1. Before running this sample,
    //  set up ADC as described in https://cloud.google.com/docs/authentication/external/set-up-adc
    //  2. Replace the project variable.
    //  3. Make sure you have the necessary permission to list storage buckets: "storage.buckets.list"
    Args:
        project_id: The project id of your Google Cloud project.
    """

    # Construct the Google credentials object which obtains the default configuration from your
    # working environment.
    # google.auth.default() will give you ComputeEngineCredentials
    # if you are on a GCE (or other metadata server supported environments).
    credentials, project_id = google.auth.default()
    # If you are authenticating to a Cloud API, you can let the library include the default scope,
    # https://www.googleapis.com/auth/cloud-platform, because IAM is used to provide fine-grained
    # permissions for Cloud.
    # If you need to provide a scope, specify it as follows:
    # credentials = google.auth.default(scopes=scope)
    # For more information on scopes to use,
    # see: https://developers.google.com/identity/protocols/oauth2/scopes

    # Construct the Storage client.
    # storage_client = storage.Client(credentials=credentials, project=project_id)

    # buckets = storage_client.list_buckets()

    # print("Buckets:")
    # for bucket in buckets:
    #     print(bucket.name)
    # print("Listed all storage buckets.")
    # This snippet demonstrates how to list instances.
    # *NOTE*: Replace the client created below with the client required for your application.
    # Note that the credentials are not specified when constructing the client.
    # Hence, the client library will look for credentials using ADC.

    # zone = "us-central1-a"

    # instances_client = compute_v1.InstancesClient(credentials=credentials)

    # print(f"Listing instances from {project_id} in {zone}")
    # # Set the project and zone to retrieve instances present in the zone.
    # for response in instances_client.list(project=project_id, zone=zone):
    #     print(response)
    # print("####### Listing instances complete #######")

    storage_client = storage.Client(credentials=credentials, project=project_id)
    buckets = storage_client.list_buckets()
    print("Buckets:")
    for bucket in buckets:
        print(bucket.name)
    print("Listed all storage buckets.")

# [END auth_cloud_explicit_adc]
