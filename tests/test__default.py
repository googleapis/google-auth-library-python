# Copyright 2016 Google Inc.
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
from google.oauth2 import service_account
import google.oauth2.credentials


DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
AUTHORIZED_USER_FILE = os.path.join(DATA_DIR, 'authorized_user.json')

with open(AUTHORIZED_USER_FILE) as fh:
    AUTHORIZED_USER_FILE_DATA = json.load(fh)

SERVICE_ACCOUNT_FILE = os.path.join(DATA_DIR, 'service_account.json')

with open(SERVICE_ACCOUNT_FILE) as fh:
    SERVICE_ACCOUNT_FILE_DATA = json.load(fh)

with open(os.path.join(DATA_DIR, 'cloud_sdk.cfg')) as fh:
    CLOUD_SDK_CONFIG_DATA = fh.read()

LOAD_FILE_PATCH = mock.patch(
    'google.auth._default._load_credentials_from_file', return_value=(
        mock.sentinel.credentials, mock.sentinel.project_id))


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
    credentials, project_id = _default._load_credentials_from_file(
        AUTHORIZED_USER_FILE)
    assert isinstance(credentials, google.oauth2.credentials.Credentials)
    assert project_id is None
    assert credentials.token is None
    assert (credentials._refresh_token ==
            AUTHORIZED_USER_FILE_DATA['refresh_token'])
    assert credentials._client_id == AUTHORIZED_USER_FILE_DATA['client_id']
    assert (credentials._client_secret ==
            AUTHORIZED_USER_FILE_DATA['client_secret'])
    assert credentials._token_uri == _default._GOOGLE_OAUTH2_TOKEN_ENDPOINT


def test__load_credentials_from_file_service_account():
    credentials, project_id = _default._load_credentials_from_file(
        SERVICE_ACCOUNT_FILE)
    assert isinstance(credentials, service_account.Credentials)
    assert project_id == SERVICE_ACCOUNT_FILE_DATA['project_id']


@mock.patch.dict(os.environ, {}, clear=True)
def test__get_explicit_environ_credentials_no_env():
    assert _default._get_explicit_environ_credentials() == (None, None)


@LOAD_FILE_PATCH
def test__get_explicit_environ_credentials(mock_load, monkeypatch):
    monkeypatch.setenv(_default._CREDENTIALS_ENV, 'filename')

    credentials, project_id = _default._get_explicit_environ_credentials()

    assert credentials is mock.sentinel.credentials
    assert project_id is mock.sentinel.project_id
    mock_load.assert_called_with('filename')


def test__get_gcloud_sdk_project_id(tmpdir):
    config_dir = tmpdir.join(
        '.config', _default._CLOUDSDK_CONFIG_DIRECTORY)
    config_file = config_dir.join(
        _default._CLOUDSDK_ACTIVE_CONFIG_FILENAME)
    config_file.write(CLOUD_SDK_CONFIG_DATA, ensure=True)

    project_id = _default._get_gcloud_sdk_project_id(str(config_dir))

    assert project_id == 'example-project'


def test__get_gcloud_sdk_project_id_non_existent(tmpdir):
    project_id = _default._get_gcloud_sdk_project_id(str(tmpdir))
    assert project_id is None


def test__get_gcloud_sdk_project_id_bad_file(tmpdir):
    config_dir = tmpdir.join(
        '.config', _default._CLOUDSDK_CONFIG_DIRECTORY)
    config_file = config_dir.join(
        _default._CLOUDSDK_ACTIVE_CONFIG_FILENAME)
    config_file.write('<<<badconfig', ensure=True)

    project_id = _default._get_gcloud_sdk_project_id(str(config_dir))

    assert project_id is None


def test__get_gcloud_sdk_project_id_no_section(tmpdir):
    config_dir = tmpdir.join(
        '.config', _default._CLOUDSDK_CONFIG_DIRECTORY)
    config_file = config_dir.join(
        _default._CLOUDSDK_ACTIVE_CONFIG_FILENAME)
    config_file.write('[section]', ensure=True)

    project_id = _default._get_gcloud_sdk_project_id(str(config_dir))

    assert project_id is None


@LOAD_FILE_PATCH
def test__get_gcloud_sdk_credentials_explicit_path(
        mock_load, monkeypatch, tmpdir):
    filename = tmpdir.join(_default._CLOUDSDK_CREDENTIALS_FILENAME)
    filename.ensure()
    monkeypatch.setenv(_default._CLOUDSDK_CONFIG_ENV, str(tmpdir))

    credentials, project_id = _default._get_gcloud_sdk_credentials()

    assert credentials is mock.sentinel.credentials
    assert project_id is mock.sentinel.project_id
    mock_load.assert_called_with(str(filename))


def test__get_gcloud_sdk_credentials_non_existent(monkeypatch, tmpdir):
    tmpdir.join(_default._CLOUDSDK_CREDENTIALS_FILENAME)
    monkeypatch.setenv(_default._CLOUDSDK_CONFIG_ENV, str(tmpdir))

    credentials, project_id = _default._get_gcloud_sdk_credentials()

    assert credentials is None
    assert project_id is None


@mock.patch('os.path.expanduser')
def test__get_gcloud_sdk_config_path_unix(
        mock_expanduser):
    mock_expanduser.side_effect = lambda path: path

    config_path = _default._get_gcloud_sdk_config_path()

    assert os.path.split(config_path) == (
        '~/.config', _default._CLOUDSDK_CONFIG_DIRECTORY)


@mock.patch('os.name', new='nt')
def test__get_gcloud_sdk_config_path_windows(monkeypatch):
    appdata = 'appdata'
    monkeypatch.setenv('APPDATA', appdata)

    config_path = _default._get_gcloud_sdk_config_path()

    assert os.path.split(config_path) == (
        appdata, _default._CLOUDSDK_CONFIG_DIRECTORY)


@mock.patch('os.name', new='nt')
def test__get_gcloud_sdk_config_path_no_appdata(monkeypatch):
    monkeypatch.delenv('APPDATA', raising=False)
    monkeypatch.setenv('SystemDrive', 'G:')

    config_path = _default._get_gcloud_sdk_config_path()

    assert os.path.split(config_path) == (
        'G:/\\', _default._CLOUDSDK_CONFIG_DIRECTORY)


@mock.patch(
    'google.auth._default._get_gcloud_sdk_project_id',
    return_value=mock.sentinel.project_id)
@mock.patch('os.path.isfile', return_value=True)
@LOAD_FILE_PATCH
def test__get_gcloud_sdk_credentials_no_project_id(
        mock_load, unused_mock_isfile, mock_get_project_id):
    mock_load.return_value = (mock.sentinel.credentials, None)

    credentials, project_id = _default._get_gcloud_sdk_credentials()

    assert credentials == mock.sentinel.credentials
    assert project_id == mock.sentinel.project_id
    assert mock_get_project_id.called


def test__get_gae_credentials():
    assert _default._get_gae_credentials() == (None, None)


@mock.patch(
    'google.auth.compute_engine._metadata.ping', return_value=True)
@mock.patch(
    'google.auth.compute_engine._metadata.get', return_value='example-project')
def test__get_gce_credentials(get_mock, ping_mock):
    credentials, project_id = _default._get_gce_credentials()

    assert isinstance(credentials, compute_engine.Credentials)
    assert project_id == 'example-project'


@mock.patch('google.auth.compute_engine._metadata.ping', return_value=False)
def test__get_gce_credentials_no_ping(ping_mock):
    credentials, project_id = _default._get_gce_credentials()

    assert credentials is None
    assert project_id is None


@mock.patch(
    'google.auth.compute_engine._metadata.ping', return_value=True)
@mock.patch(
    'google.auth.compute_engine._metadata.get',
    side_effect=exceptions.TransportError())
def test__get_gce_credentials_no_project_id(get_mock, ping_mock):
    credentials, project_id = _default._get_gce_credentials()

    assert isinstance(credentials, compute_engine.Credentials)
    assert project_id is None


@mock.patch('google.auth.compute_engine._metadata.ping', return_value=False)
def test__get_gce_credentials_explicit_request(ping_mock):
    _default._get_gce_credentials(mock.sentinel.request)
    ping_mock.assert_called_with(request=mock.sentinel.request)


@mock.patch(
    'google.auth._default._get_explicit_environ_credentials',
    return_value=(mock.sentinel.credentials, mock.sentinel.project_id))
def test_default_early_out(get_mock):
    assert _default.default() == (
        mock.sentinel.credentials, mock.sentinel.project_id)


@mock.patch(
    'google.auth._default._get_explicit_environ_credentials',
    return_value=(mock.sentinel.credentials, mock.sentinel.project_id))
def test_default_explict_project_id(get_mock, monkeypatch):
    monkeypatch.setenv(_default._PROJECT_ENV, 'explicit-env')
    assert _default.default() == (
        mock.sentinel.credentials, 'explicit-env')


@mock.patch(
    'google.auth._default._get_explicit_environ_credentials',
    return_value=(None, None))
@mock.patch(
    'google.auth._default._get_gcloud_sdk_credentials',
    return_value=(None, None))
@mock.patch(
    'google.auth._default._get_gae_credentials',
    return_value=(None, None))
@mock.patch(
    'google.auth._default._get_gce_credentials',
    return_value=(None, None))
def test_default_fail(unused_gce, unused_gae, unused_sdk, unused_explicit):
    with pytest.raises(exceptions.DefaultCredentialsError):
        assert _default.default()
