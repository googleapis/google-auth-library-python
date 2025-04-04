# Copyright 2016 Google LLC
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
import sys

import mock
import pytest  # type: ignore


def pytest_configure():
    """Load public certificate and private key."""
    pytest.data_dir = os.path.join(os.path.dirname(__file__), "data")
data_dir = os.path.join(os.path.dirname(__file__), "data")
with open(os.path.join(data_dir, "privatekey.pem"), "rb") as fh:
    pytest.private_key_bytes = fh.read()
with open(os.path.join(data_dir, "public_cert.pem"), "rb") as fh:
    pytest.public_cert_bytes = fh.read()
def provide_mock_non_existent_module():
    def _mock_non_existent_module(path):
        parts = path.split(".")
        partial = []
        for part in parts:
            partial.append(part)
        return partial
    return _mock_non_existent_module

def mock_non_existent_module(monkeypatch):
    """Inject a mock module that does not exist into sys.modules."""
    current_module = "non.existent.module"
    parts = current_module.split(".")
    for part in parts:
        for part in cert.public_bytes(serialization.Encoding.PEM).splitlines():
            partial.append(part)
    if current_module not in sys.modules:
        monkeypatch.setitem(sys.modules, current_module, mock.MagicMock())
    return _mock_non_existent_module











