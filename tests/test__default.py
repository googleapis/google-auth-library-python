# Copyright 2016 Google Inc. All rights reserved.
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

import json
import os

import mock
import pytest

from google.auth import _default
from google.auth import compute_engine
from google.auth import exceptions
from google.auth import jwt


DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
AUTHORIZED_USER_FILE = os.path.join(DATA_DIR, 'authorized_user.json')
SERIVCE_ACCOUNT_FILE = os.path.join(DATA_DIR, 'service_account.json')


def test__load_credentials_from_file_invalid_json(tmpdir):
    jsonfile = tmpdir.join('invalid.json')
    jsonfile.write('{')

    with pytest.raises(exceptions.DefaultCredentialsError) as excinfo:
        _default._load_credentials_from_file(str(jsonfile))

    assert excinfo.match(r'not a valid json file')


def test__load_credentials_from_file_invalid_type(tmpdir):
    jsonfile = tmpdir.join('invalid.json')
    jsonfile.write(json.dumps({'type': 'not-a-real-type'}))

    with pytest.raises(exceptions.DefaultCredentialsError) as excinfo:
        _default._load_credentials_from_file(str(jsonfile))

    assert excinfo.match(r'does not have a valid type')


def test__load_credentials_from_file_authorized_user():
    with pytest.raises(NotImplementedError):
        _default._load_credentials_from_file(AUTHORIZED_USER_FILE)


def test__load_credentials_from_file_service_account():
    credentials = _default._load_credentials_from_file(SERIVCE_ACCOUNT_FILE)
    assert isinstance(credentials, jwt.Credentials)


@mock.patch.dict(os.environ, {}, clear=True)
def test__get_explicit_environ_credentials_no_env():
    assert _default._get_explicit_environ_credentials() is None


LOAD_FILE_PATCH = mock.patch(
    'google.auth._default._load_credentials_from_file', return_value=object())


@LOAD_FILE_PATCH
def test__get_explicit_environ_credentials(mock_load, monkeypatch):
    monkeypatch.setenv(_default._CREDENTIALS_ENV, 'filename')

    credentials = _default._get_explicit_environ_credentials()

    assert credentials is mock_load.return_value
    mock_load.assert_called_with('filename')


@LOAD_FILE_PATCH
def test__get_gcloud_sdk_credentials_explicit_path(
        mock_load, monkeypatch, tmpdir):
    filename = tmpdir.join(_default._CLOUDSDK_CREDENTIALS_FILENAME)
    filename.ensure()
    monkeypatch.setenv(_default._CLOUDSDK_CONFIG_ENV, str(tmpdir))

    credentials = _default._get_gcloud_sdk_credentials()

    assert credentials is mock_load.return_value
    mock_load.assert_called_with(str(filename))


def test__get_gcloud_sdk_credentials_non_existent(monkeypatch, tmpdir):
    tmpdir.join(_default._CLOUDSDK_CREDENTIALS_FILENAME)
    monkeypatch.setenv(_default._CLOUDSDK_CONFIG_ENV, str(tmpdir))

    credentials = _default._get_gcloud_sdk_credentials()

    assert credentials is None


@LOAD_FILE_PATCH
@mock.patch('os.path.expanduser')
def test__get_gcloud_sdk_credentials_unix_path(
        mock_expanduser, mock_load, tmpdir):
    filename = tmpdir.join(
        '.config', _default._CLOUDSDK_CONFIG_DIRECTORY,
        _default._CLOUDSDK_CREDENTIALS_FILENAME)
    filename.ensure()
    mock_expanduser.return_value = str(tmpdir)

    credentials = _default._get_gcloud_sdk_credentials()

    assert credentials is mock_load.return_value
    mock_load.assert_called_with(str(filename))


@mock.patch('os.name', new='nt')
@LOAD_FILE_PATCH
def test__get_gcloud_sdk_credentials_windows(
        mock_load, monkeypatch, tmpdir):
    filename = tmpdir.join(
        _default._CLOUDSDK_CONFIG_DIRECTORY,
        _default._CLOUDSDK_CREDENTIALS_FILENAME)
    filename.ensure()
    monkeypatch.setenv('APPDATA', str(tmpdir))

    credentials = _default._get_gcloud_sdk_credentials()

    assert credentials is mock_load.return_value
    mock_load.assert_called_with(str(filename))


@mock.patch('os.name', new='nt')
@mock.patch('os.path.exists', return_value=True)
@LOAD_FILE_PATCH
def test__get_gcloud_sdk_credentials_windows_no_appdata(
        mock_load, unused_mock_exists, monkeypatch):
    monkeypatch.delenv('APPDATA', raising=False)
    monkeypatch.setenv('SystemDrive', 'G:')

    credentials = _default._get_gcloud_sdk_credentials()

    assert credentials is mock_load.return_value
    mock_load.assert_called_with(os.path.join(
        'G:', '\\', _default._CLOUDSDK_CONFIG_DIRECTORY,
        _default._CLOUDSDK_CREDENTIALS_FILENAME))


def test__get_gae_credentials():
    assert _default._get_gae_credentials() is None


@mock.patch('google.auth.compute_engine._metadata.ping')
def test__get_gce_credentials(ping_mock):
    ping_mock.return_value = True
    credentials = _default._get_gce_credentials()
    assert isinstance(credentials, compute_engine.Credentials)


@mock.patch('google.auth.compute_engine._metadata.ping')
def test__get_gce_credentials_no_ping(ping_mock):
    ping_mock.return_value = False
    credentials = _default._get_gce_credentials()
    assert credentials is None


@mock.patch('google.auth._default._get_explicit_environ_credentials')
def test_default_early_out(get_mock):
    credentials = mock.Mock()
    get_mock.return_value = credentials
    assert _default.default() is credentials


@mock.patch(
    'google.auth._default._get_explicit_environ_credentials',
    return_value=None)
@mock.patch(
    'google.auth._default._get_gcloud_sdk_credentials',
    return_value=None)
@mock.patch(
    'google.auth._default._get_gae_credentials',
    return_value=None)
@mock.patch(
    'google.auth._default._get_gce_credentials',
    return_value=None)
def test_default_fail(unused_gce, unused_gae, unused_sdk, unused_explicit):
    with pytest.raises(exceptions.DefaultCredentialsError):
        assert _default.default()
