# Copyright 2020 Google LLC
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
from unittest import mock
import pytest
from google.auth.transport import _mtls_helper
from google.auth import environment_vars

class TestEnvVarsPrecedence:
    def test_use_client_cert_precedence(self):
        # GOOGLE_API_USE_CLIENT_CERTIFICATE takes precedence
        with mock.patch.dict(os.environ, {
            environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE: "true",
            environment_vars.CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE: "false"
        }):
            assert _mtls_helper.check_use_client_cert() is True

        with mock.patch.dict(os.environ, {
            environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE: "false",
            environment_vars.CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE: "true"
        }):
            assert _mtls_helper.check_use_client_cert() is False

    def test_use_client_cert_fallback(self):
        # Fallback to CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE if GOOGLE_API_USE_CLIENT_CERTIFICATE is unset
        with mock.patch.dict(os.environ, {
            environment_vars.CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE: "true"
        }):
             # Ensure GOOGLE_API_USE_CLIENT_CERTIFICATE is not set
             if environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE in os.environ:
                 del os.environ[environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE]
             assert _mtls_helper.check_use_client_cert() is True

        with mock.patch.dict(os.environ, {
            environment_vars.CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE: "false"
        }):
             if environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE in os.environ:
                 del os.environ[environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE]
             assert _mtls_helper.check_use_client_cert() is False

    def test_cert_config_path_precedence(self):
        # GOOGLE_API_CERTIFICATE_CONFIG takes precedence
        google_path = "/path/to/google/config"
        cloudsdk_path = "/path/to/cloudsdk/config"

        with mock.patch.dict(os.environ, {
            environment_vars.GOOGLE_API_CERTIFICATE_CONFIG: google_path,
            environment_vars.CLOUDSDK_CONTEXT_AWARE_CERTIFICATE_CONFIG_FILE_PATH: cloudsdk_path
        }):
            with mock.patch("os.path.exists", return_value=True):
                assert _mtls_helper._get_cert_config_path() == google_path

    def test_cert_config_path_fallback(self):
        # Fallback to CLOUDSDK_CONTEXT_AWARE_CERTIFICATE_CONFIG_FILE_PATH if GOOGLE_API_CERTIFICATE_CONFIG is unset
        cloudsdk_path = "/path/to/cloudsdk/config"

        with mock.patch.dict(os.environ, {
            environment_vars.CLOUDSDK_CONTEXT_AWARE_CERTIFICATE_CONFIG_FILE_PATH: cloudsdk_path
        }):
             if environment_vars.GOOGLE_API_CERTIFICATE_CONFIG in os.environ:
                 del os.environ[environment_vars.GOOGLE_API_CERTIFICATE_CONFIG]

             with mock.patch("os.path.exists", return_value=True):
                assert _mtls_helper._get_cert_config_path() == cloudsdk_path

    @mock.patch("builtins.open", autospec=True)
    def test_check_use_client_cert_config_fallback(self, mock_file):
        # Test fallback for config file when determining if client cert should be used
        cloudsdk_path = "/path/to/cloudsdk/config"

        mock_file.side_effect = mock.mock_open(
            read_data='{"cert_configs": {"workload": "exists"}}'
        )

        with mock.patch.dict(os.environ, {
            environment_vars.CLOUDSDK_CONTEXT_AWARE_CERTIFICATE_CONFIG_FILE_PATH: cloudsdk_path
        }):
             if environment_vars.GOOGLE_API_CERTIFICATE_CONFIG in os.environ:
                 del os.environ[environment_vars.GOOGLE_API_CERTIFICATE_CONFIG]
             if environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE in os.environ:
                 del os.environ[environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE]
             if environment_vars.CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE in os.environ:
                 del os.environ[environment_vars.CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE]

             assert _mtls_helper.check_use_client_cert() is True
