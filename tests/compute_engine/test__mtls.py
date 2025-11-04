# -*- coding: utf-8 -*-
#
# Copyright 2024 Google LLC
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
#

import mock
import pytest  # type: ignore

from google.auth import environment_vars, exceptions
from google.auth.compute_engine import _mtls


@pytest.fixture
def mock_mds_mtls_config():
    return _mtls.MdsMtlsConfig(
        ca_cert_path="/fake/ca.crt", client_combined_cert_path="/fake/client.key"
    )


def test__parse_mds_mode_default(monkeypatch):
    monkeypatch.delenv(environment_vars.GCE_METADATA_MTLS_MODE, raising=False)
    assert _mtls._parse_mds_mode() == _mtls.MdsMtlsMode.DEFAULT


@pytest.mark.parametrize(
    "mode_str, expected_mode",
    [
        ("strict", _mtls.MdsMtlsMode.STRICT),
        ("none", _mtls.MdsMtlsMode.NONE),
        ("default", _mtls.MdsMtlsMode.DEFAULT),
        ("STRICT", _mtls.MdsMtlsMode.STRICT),
    ],
)
def test__parse_mds_mode_valid(monkeypatch, mode_str, expected_mode):
    monkeypatch.setenv(environment_vars.GCE_METADATA_MTLS_MODE, mode_str)
    assert _mtls._parse_mds_mode() == expected_mode


def test__parse_mds_mode_invalid(monkeypatch):
    monkeypatch.setenv(environment_vars.GCE_METADATA_MTLS_MODE, "invalid_mode")
    with pytest.raises(ValueError):
        _mtls._parse_mds_mode()


@mock.patch("os.path.exists")
def test__certs_exist_true(mock_exists, mock_mds_mtls_config):
    mock_exists.return_value = True
    assert _mtls._certs_exist(mock_mds_mtls_config) is True


@mock.patch("os.path.exists")
def test__certs_exist_false(mock_exists, mock_mds_mtls_config):
    mock_exists.return_value = False
    assert _mtls._certs_exist(mock_mds_mtls_config) is False


@pytest.mark.parametrize(
    "mtls_mode, certs_exist, expected_result",
    [
        ("strict", True, True),
        ("strict", False, exceptions.MutualTLSChannelError),
        ("none", True, False),
        ("none", False, False),
        ("default", True, True),
        ("default", False, False),
    ],
)
@mock.patch("os.path.exists")
def test_should_use_mds_mtls(
    mock_exists, monkeypatch, mtls_mode, certs_exist, expected_result
):
    monkeypatch.setenv(environment_vars.GCE_METADATA_MTLS_MODE, mtls_mode)
    mock_exists.return_value = certs_exist

    if isinstance(expected_result, type) and issubclass(expected_result, Exception):
        with pytest.raises(expected_result):
            _mtls.should_use_mds_mtls()
    else:
        assert _mtls.should_use_mds_mtls() is expected_result


@mock.patch("ssl.create_default_context")
def test_mds_mtls_adapter_init(mock_ssl_context, mock_mds_mtls_config):
    adapter = _mtls.MdsMtlsAdapter(mock_mds_mtls_config)
    mock_ssl_context.assert_called_once()
    adapter.ssl_context.load_verify_locations.assert_called_once_with(
        cafile=mock_mds_mtls_config.ca_cert_path
    )
    adapter.ssl_context.load_cert_chain.assert_called_once_with(
        certfile=mock_mds_mtls_config.client_combined_cert_path
    )


@mock.patch("requests.Session")
@mock.patch("google.auth.compute_engine._mtls.MdsMtlsAdapter")
def test_create_session(mock_adapter, mock_session, mock_mds_mtls_config):
    session_instance = mock_session.return_value
    session = _mtls.create_session(mock_mds_mtls_config)
    assert session is session_instance
    mock_adapter.assert_called_once_with(mock_mds_mtls_config)
    session_instance.mount.assert_called_once_with(
        "https://", mock_adapter.return_value
    )


@mock.patch("ssl.create_default_context")
@mock.patch("requests.adapters.HTTPAdapter.proxy_manager_for")
def test_mds_mtls_adapter_proxy_manager_for(
    mock_proxy_manager_for, mock_ssl_context, mock_mds_mtls_config
):
    adapter = _mtls.MdsMtlsAdapter(mock_mds_mtls_config)
    adapter.proxy_manager_for("test_proxy")
    mock_proxy_manager_for.assert_called_once_with(
        "test_proxy", ssl_context=adapter.ssl_context
    )
