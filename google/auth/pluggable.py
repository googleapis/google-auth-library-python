# Copyright 2022 Google LLC
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

"""Pluggable Credentials.
Using Executable-sourced credentials with OIDC and SAML

**Executable-sourced credentials**
For executable-sourced credentials, a local executable is used to retrieve the 3rd party token. 
The executable must handle providing a valid, unexpired OIDC ID token or SAML assertion in JSON format
to stdout.

To use executable-sourced credentials, the `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES`
environment variable must be set to `1`.

To generate an executable-sourced workload identity configuration, run the following command:

```bash
# Generate a configuration file for executable-sourced credentials.
gcloud iam workload-identity-pools create-cred-config \
    projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$PROVIDER_ID \
    --service-account=$SERVICE_ACCOUNT_EMAIL \
    --subject-token-type=$SUBJECT_TOKEN_TYPE \
    # The absolute path for the program, including arguments.
    # e.g. --executable-command="/path/to/command --foo=bar"
    --executable-command=$EXECUTABLE_COMMAND \
    # Optional argument for the executable timeout. Defaults to 30s.
    # --executable-timeout-millis=$EXECUTABLE_TIMEOUT \
    # Optional argument for the absolute path to the executable output file.
    # See below on how this argument impacts the library behaviour.
    # --executable-output-file=$EXECUTABLE_OUTPUT_FILE \
    --output-file /path/to/generated/config.json
```
Where the following variables need to be substituted:
- `$PROJECT_NUMBER`: The Google Cloud project number.
- `$POOL_ID`: The workload identity pool ID.
- `$PROVIDER_ID`: The OIDC or SAML provider ID.
- `$SERVICE_ACCOUNT_EMAIL`: The email of the service account to impersonate.
- `$SUBJECT_TOKEN_TYPE`: The subject token type.
- `$EXECUTABLE_COMMAND`: The full command to run, including arguments. Must be an absolute path to the program. 

To retrieve the 3rd party token, the library will call the executable 
using the command specified. The executable's output must adhere to the response format 
specified below. It must output the response to stdout.

A sample successful executable OIDC response:
```json
{
  "version": 1,
  "success": true,
  "token_type": "urn:ietf:params:oauth:token-type:id_token",
  "id_token": "HEADER.PAYLOAD.SIGNATURE",
  "expiration_time": 1620499962
}
```

A sample successful executable SAML response:
```json
{
  "version": 1,
  "success": true,
  "token_type": "urn:ietf:params:oauth:token-type:saml2",
  "saml_response": "...",
  "expiration_time": 1620499962
}
```
A sample executable error response:
```json
{
  "version": 1,
  "success": false,
  "code": "401",
  "message": "Caller not authorized."
}
```
These are all required fields for an error response. The code and message
fields will be used by library as part of the thrown exception.

Response format fields summary:
  * `version`: The version of the JSON output. Currently only version 1 is supported.
  * `success`: The status of the response. When true, the response must contain the 3rd party token, 
    token type, and expiration. The executable must also exit with exit code 0.
    When false, the response must contain the error code and message fields and exit with a non-zero value.
  * `token_type`: The 3rd party subject token type. Must be *urn:ietf:params:oauth:token-type:jwt*, 
     *urn:ietf:params:oauth:token-type:id_token*, or *urn:ietf:params:oauth:token-type:saml2*.
  * `id_token`: The 3rd party OIDC token.
  * `saml_response`: The 3rd party SAML response.
  * `expiration_time`: The 3rd party subject token expiration time in seconds (unix epoch time).
  * `code`: The error code string.
  * `message`: The error message.

All response types must include both the `version` and `success` fields.
 * Successful responses must include the `token_type`, `expiration_time`, and one of
   `id_token` or `saml_response`.
 * Error responses must include both the `code` and `message` fields.

The library will populate the following environment variables when the executable is run:
  * `GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE`: The audience field from the credential configuration. Always present.
  * `GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL`: The service account email. Only present when service account impersonation is used.
  * `GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE`: The output file location from the credential configuration. Only present when specified in the credential configuration. 

These environment variables can be used by the executable to avoid hard-coding these values.

Security considerations
The following security practices are highly recommended:  
  * Access to the script should be restricted as it will be displaying credentials to stdout. This ensures that rogue processes do not gain  access to the script.
  * The configuration file should not be modifiable. Write access should be restricted to avoid processes modifying the executable command portion.

Given the complexity of using executable-sourced credentials, it is recommended to use
the existing supported mechanisms (file-sourced/URL-sourced) for providing 3rd party
credentials unless they do not meet your specific requirements.

You can now [use the Auth library](#using-external-identities) to call Google Cloud
resources from an OIDC or SAML provider.
"""

try:
    from collections.abc import Mapping
# Python 2.7 compatibility
except ImportError:  # pragma: NO COVER
    from collections import Mapping
import io
import json
import os
import subprocess
import sys
import time

from google.auth import _helpers
from google.auth import exceptions
from google.auth import external_account

# The max supported executable spec version.
EXECUTABLE_SUPPORTED_MAX_VERSION = 1


class Credentials(external_account.Credentials):
    """External account credentials sourced from executables."""

    def __init__(
        self,
        audience,
        subject_token_type,
        token_url,
        credential_source,
        service_account_impersonation_url=None,
        client_id=None,
        client_secret=None,
        quota_project_id=None,
        scopes=None,
        default_scopes=None,
        workforce_pool_user_project=None,
    ):
        """Instantiates an external account credentials object from a executables.

        Args:
            audience (str): The STS audience field.
            subject_token_type (str): The subject token type.
            token_url (str): The STS endpoint URL.
            credential_source (Mapping): The credential source dictionary used to
                provide instructions on how to retrieve external credential to be
                exchanged for Google access tokens.

                Example credential_source for pluggable credential:

                    {
                        "executable": {
                            "command": "/path/to/get/credentials.sh --arg1=value1 --arg2=value2",
                            "timeout_millis": 5000,
                            "output_file": "/path/to/generated/cached/credentials"
                        }
                    }

            service_account_impersonation_url (Optional[str]): The optional service account
                impersonation getAccessToken URL.
            client_id (Optional[str]): The optional client ID.
            client_secret (Optional[str]): The optional client secret.
            quota_project_id (Optional[str]): The optional quota project ID.
            scopes (Optional[Sequence[str]]): Optional scopes to request during the
                authorization grant.
            default_scopes (Optional[Sequence[str]]): Default scopes passed by a
                Google client library. Use 'scopes' for user-defined scopes.
            workforce_pool_user_project (Optona[str]): The optional workforce pool user
                project number when the credential corresponds to a workforce pool and not
                a workload Pluggable. The underlying principal must still have
                serviceusage.services.use IAM permission to use the project for
                billing/quota.

        Raises:
            google.auth.exceptions.RefreshError: If an error is encountered during
                access token retrieval logic.
            ValueError: For invalid parameters.

        .. note:: Typically one of the helper constructors
            :meth:`from_file` or
            :meth:`from_info` are used instead of calling the constructor directly.
        """

        super(Credentials, self).__init__(
            audience=audience,
            subject_token_type=subject_token_type,
            token_url=token_url,
            credential_source=credential_source,
            service_account_impersonation_url=service_account_impersonation_url,
            client_id=client_id,
            client_secret=client_secret,
            quota_project_id=quota_project_id,
            scopes=scopes,
            default_scopes=default_scopes,
            workforce_pool_user_project=workforce_pool_user_project,
        )
        if not isinstance(credential_source, Mapping):
            self._credential_source_executable = None
            raise ValueError(
                "Missing credential_source. The credential_source is not a dict."
            )
        self._credential_source_executable = credential_source.get("executable")
        if not self._credential_source_executable:
            raise ValueError(
                "Missing credential_source. An 'executable' must be provided."
            )
        self._credential_source_executable_command = self._credential_source_executable.get(
            "command"
        )
        self._credential_source_executable_timeout_millis = self._credential_source_executable.get(
            "timeout_millis"
        )
        self._credential_source_executable_output_file = self._credential_source_executable.get(
            "output_file"
        )

        if not self._credential_source_executable_command:
            raise ValueError(
                "Missing command field. Executable command must be provided."
            )
        if not self._credential_source_executable_timeout_millis:
            self._credential_source_executable_timeout_millis = 30 * 1000
        elif (
            self._credential_source_executable_timeout_millis < 5 * 1000
            or self._credential_source_executable_timeout_millis > 120 * 1000
        ):
            raise ValueError("Timeout must be between 5 and 120 seconds.")

    @_helpers.copy_docstring(external_account.Credentials)
    def retrieve_subject_token(self, request):
        env_allow_executables = os.environ.get(
            "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"
        )
        if env_allow_executables != "1":
            raise ValueError(
                "Executables need to be explicitly allowed (set GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES to '1') to run."
            )

        # Check output file.
        if self._credential_source_executable_output_file is not None:
            try:
                with open(
                    self._credential_source_executable_output_file
                ) as output_file:
                    response = json.load(output_file)
            except Exception:
                pass
            else:
                try:
                    # If the cached response is expired, _parse_subject_token will raise an error which will be ignored and we will call the executable again.
                    subject_token = self._parse_subject_token(response)
                except ValueError:
                    raise
                except exceptions.RefreshError:
                    pass
                else:
                    return subject_token

        if not _helpers.is_python_3():
            raise exceptions.RefreshError(
                "Pluggable auth is only supported for python 3.6+"
            )

        # Inject env vars.
        env = os.environ.copy()
        env["GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE"] = self._audience
        env["GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE"] = self._subject_token_type
        env[
            "GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE"
        ] = "0"  # Always set to 0 until interactive mode is implemented.
        if self._service_account_impersonation_url is not None:
            env[
                "GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL"
            ] = self.service_account_email
        if self._credential_source_executable_output_file is not None:
            env[
                "GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE"
            ] = self._credential_source_executable_output_file

        try:
            result = subprocess.run(
                self._credential_source_executable_command.split(),
                timeout=self._credential_source_executable_timeout_millis / 1000,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
            )
            if result.returncode != 0:
                raise exceptions.RefreshError(
                    "Executable exited with non-zero return code {}. Error: {}".format(
                        result.returncode, result.stdout
                    )
                )
        except Exception:
            raise
        else:
            try:
                data = result.stdout.decode("utf-8")
                response = json.loads(data)
                subject_token = self._parse_subject_token(response)
            except Exception:
                raise

        return subject_token

    @classmethod
    def from_info(cls, info, **kwargs):
        """Creates a Pluggable Credentials instance from parsed external account info.

        Args:
            info (Mapping[str, str]): The Pluggable external account info in Google
                format.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            google.auth.pluggable.Credentials: The constructed
                credentials.

        Raises:
            ValueError: For invalid parameters.
        """
        return cls(
            audience=info.get("audience"),
            subject_token_type=info.get("subject_token_type"),
            token_url=info.get("token_url"),
            service_account_impersonation_url=info.get(
                "service_account_impersonation_url"
            ),
            client_id=info.get("client_id"),
            client_secret=info.get("client_secret"),
            credential_source=info.get("credential_source"),
            quota_project_id=info.get("quota_project_id"),
            workforce_pool_user_project=info.get("workforce_pool_user_project"),
            **kwargs
        )

    @classmethod
    def from_file(cls, filename, **kwargs):
        """Creates an Pluggable Credentials instance from an external account json file.

        Args:
            filename (str): The path to the Pluggable external account json file.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            google.auth.pluggable.Credentials: The constructed
                credentials.
        """
        with io.open(filename, "r", encoding="utf-8") as json_file:
            data = json.load(json_file)
            return cls.from_info(data, **kwargs)

    def _parse_subject_token(self, response):
        if "version" not in response:
            raise ValueError("The executable response is missing the version field.")
        if response["version"] > EXECUTABLE_SUPPORTED_MAX_VERSION:
            raise exceptions.RefreshError(
                "Executable returned unsupported version {}.".format(
                    response["version"]
                )
            )
        if "success" not in response:
            raise ValueError("The executable response is missing the success field.")
        if not response["success"]:
            if "code" not in response or "message" not in response:
                raise ValueError(
                    "Error code and message fields are required in the response."
                )
            raise exceptions.RefreshError(
                "Executable returned unsuccessful response: code: {}, message: {}.".format(
                    response["code"], response["message"]
                )
            )
        if "expiration_time" not in response:
            raise ValueError(
                "The executable response is missing the expiration_time field."
            )
        if response["expiration_time"] < time.time():
            raise exceptions.RefreshError(
                "The token returned by the executable is expired."
            )
        if "token_type" not in response:
            raise ValueError("The executable response is missing the token_type field.")
        if (
            response["token_type"] == "urn:ietf:params:oauth:token-type:jwt"
            or response["token_type"] == "urn:ietf:params:oauth:token-type:id_token"
        ):  # OIDC
            return response["id_token"]
        elif response["token_type"] == "urn:ietf:params:oauth:token-type:saml2":  # SAML
            return response["saml_response"]
        else:
            raise exceptions.RefreshError("Executable returned unsupported token type.")
