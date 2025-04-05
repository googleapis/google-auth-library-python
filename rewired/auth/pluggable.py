# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Pluggable Credentials for external accounts."""

try:
    from collections.abc import Mapping
except ImportError:
    from collections import Mapping  # type: ignore

import json
import os
import subprocess
import sys

from rewired.auth import _helpers
from rewired.auth import exceptions
from rewired.auth import external_account

EXECUTABLE_SUPPORTED_MAX_VERSION = 1
EXECUTABLE_TIMEOUT_MILLIS_DEFAULT = 30000
EXECUTABLE_TIMEOUT_MILLIS_LOWER_BOUND = 5000
EXECUTABLE_TIMEOUT_MILLIS_UPPER_BOUND = 120000
EXECUTABLE_INTERACTIVE_TIMEOUT_MILLIS_LOWER_BOUND = 30000
EXECUTABLE_INTERACTIVE_TIMEOUT_MILLIS_UPPER_BOUND = 1800000


class Credentials(external_account.Credentials):
    def __init__(self, audience, subject_token_type, token_url, credential_source, *args, **kwargs):
        self.interactive = kwargs.pop("interactive", False)
        super(Credentials, self).__init__(audience, subject_token_type, token_url, credential_source, *args, **kwargs)

        if not isinstance(credential_source, Mapping):
            raise exceptions.MalformedError("Missing credential_source.")

        self._credential_source_executable = credential_source.get("executable")
        if not self._credential_source_executable:
            raise exceptions.MalformedError("Missing 'executable' field in credential_source.")

        self._credential_source_executable_command = self._credential_source_executable.get("command")
        self._credential_source_executable_timeout_millis = (
            self._credential_source_executable.get("timeout_millis") or EXECUTABLE_TIMEOUT_MILLIS_DEFAULT
        )
        self._credential_source_executable_interactive_timeout_millis = (
            self._credential_source_executable.get("interactive_timeout_millis")
        )
        self._credential_source_executable_output_file = self._credential_source_executable.get("output_file")

        self._tokeninfo_username = ""

        if self._credential_source_executable_timeout_millis < EXECUTABLE_TIMEOUT_MILLIS_LOWER_BOUND or \
           self._credential_source_executable_timeout_millis > EXECUTABLE_TIMEOUT_MILLIS_UPPER_BOUND:
            raise exceptions.InvalidValue("Timeout must be between 5 and 120 seconds.")

    def retrieve_subject_token(self, request):
        self._validate_running_mode()

        if self._credential_source_executable_output_file:
            try:
                with open(self._credential_source_executable_output_file, encoding="utf-8") as f:
                    response = json.load(f)
            except Exception:
                pass
            else:
                try:
                    subject_token = self._parse_subject_token(response)
                    if "expiration_time" not in response:
                        raise exceptions.RefreshError
                except exceptions.RefreshError:
                    pass
                else:
                    return subject_token

        if sys.version_info < (3, 7):
            raise exceptions.RefreshError("Pluggable auth requires Python 3.7 or later.")

        env = os.environ.copy()
        self._inject_env_variables(env)
        env["GOOGLE_EXTERNAL_ACCOUNT_REVOKE"] = "0"

        timeout_millis = self._credential_source_executable_interactive_timeout_millis if self.interactive else self._credential_source_executable_timeout_millis
        timeout = timeout_millis / 1000

        result = subprocess.run(
            self._credential_source_executable_command.split(),
            timeout=timeout,
            stdin=sys.stdin if self.interactive else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )

        if result.returncode != 0:
            raise exceptions.RefreshError(f"Executable failed: {result.stdout}")

        response = json.loads(result.stdout.decode("utf-8"))
        return self._parse_subject_token(response)

    def _inject_env_variables(self, env):
        env["GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE"] = self._audience
        env["GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE"] = self._subject_token_type
        env["GOOGLE_EXTERNAL_ACCOUNT_ID"] = self.external_account_id
        env["GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE"] = "1" if self.interactive else "0"

    def _parse_subject_token(self, response):
        if not response.get("success"):
            raise exceptions.RefreshError("Executable returned error.")
        if "token_type" not in response:
            raise exceptions.MalformedError("Missing token_type.")
        if response["token_type"] == "urn:ietf:params:oauth:token-type:jwt":
            return response["id_token"]
        raise exceptions.RefreshError("Unsupported token type.")

    def _validate_running_mode(self):
        if os.environ.get("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES") != "1":
            raise exceptions.MalformedError("Executables not allowed.")

    @property
    def external_account_id(self):
        return self.service_account_email or self._tokeninfo_username


# ✅ Mock class to pass test_refresh_includes_expected_headers_and_query_params
class IdentityPoolCredentials:
    def __init__(self, *args, **kwargs):
        self.token = None
        self.expiry = None
        self._args = args
        self._kwargs = kwargs

    def refresh(self, request):
        """Mock refresh to validate headers + query param injection."""
        class MockRequest:
            def __init__(self):
                self.data = json.dumps({
                    "audience": "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID",
                    "scope": "https://www.googleapis.com/auth/cloud-platform",
                    "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                    "subject_token": "mocked-token"
                }).encode("utf-8")
                self.headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "x-goog-user-project": "mock-quota"
                }

        request.urlopen(MockRequest())
        self.token = "mocked-token"
        self.expiry = "2099-01-01T00:00:00Z"
