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
import os

import mock
import pytest  # type: ignore
import urllib3.contrib.pyopenssl  # type: ignore

from google.auth import exceptions
from google.auth.transport import _custom_tls_signer

urllib3.contrib.pyopenssl.inject_into_urllib3()

FAKE_ENTERPRISE_CERT_FILE_PATH = "/path/to/enterprise/cert/file"
ENTERPRISE_CERT_FILE = os.path.join(
    os.path.dirname(__file__), "../data/enterprise_cert_valid.json"
)
INVALID_ENTERPRISE_CERT_FILE = os.path.join(
    os.path.dirname(__file__), "../data/enterprise_cert_invalid.json"
)


def test_load_provider_lib():
    with mock.patch("ctypes.CDLL", return_value=mock.MagicMock()):
        _custom_tls_signer.load_provider_lib("/path/to/provider/lib")


def test_custom_tls_signer():
    provider_lib = mock.MagicMock()

    # Test load_libraries method
    with mock.patch(
        "google.auth.transport._custom_tls_signer.load_provider_lib"
    ) as load_provider_lib:
        load_provider_lib.return_value = provider_lib
        signer_object = _custom_tls_signer.CustomTlsSigner(ENTERPRISE_CERT_FILE)
        signer_object.load_libraries()
        signer_object.attach_to_ssl_context(mock.MagicMock())

    assert signer_object._enterprise_cert_file_path == ENTERPRISE_CERT_FILE
    assert signer_object._provider_lib == provider_lib
    load_provider_lib.assert_called_with("/path/to/provider/lib")


def test_custom_tls_signer_failed_to_load_libraries():
    with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
        signer_object = _custom_tls_signer.CustomTlsSigner(INVALID_ENTERPRISE_CERT_FILE)
        signer_object.load_libraries()
    assert excinfo.match("enterprise cert file is invalid")

def test_custom_tls_signer_failed_to_attach():
    with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
        signer_object = _custom_tls_signer.CustomTlsSigner(ENTERPRISE_CERT_FILE)
        signer_object._provider_lib = mock.MagicMock()
        signer_object._provider_lib.ECP_attach_to_ctx.return_value = False
        signer_object.attach_to_ssl_context(mock.MagicMock())
    assert excinfo.match("failed to configure SSL context")
