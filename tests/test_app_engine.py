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

import datetime
import sys

import mock
import pytest
from six.moves import reload_module

from google.auth import exceptions


@pytest.fixture
def app_identity_mock(monkeypatch):
    """Mocks the google.appengine.api.app_identity module."""
    api_mock = mock.Mock()
    app_identity_mock = api_mock.app_identity

    monkeypatch.setitem(
        sys.modules, 'google.appengine', mock.Mock())
    monkeypatch.setitem(
        sys.modules, 'google.appengine.api', api_mock)

    from google.appengine.api import app_identity
    assert app_identity == app_identity_mock

    yield app_identity_mock


@pytest.fixture
def app_engine(app_identity_mock):
    from google.auth import app_engine
    reload_module(app_engine)
    yield app_engine


@pytest.fixture
def app_engine_no_apis():
    from google.auth import app_engine
    reload_module(app_engine)
    yield app_engine


class TestCredentials(object):
    def test_default_state(self, app_engine):
        credentials = app_engine.Credentials()

        # Not token acquired yet
        assert not credentials.valid
        # Expiration hasn't been set yet
        assert not credentials.expired
        # Scopes are required
        assert not credentials.scopes
        assert credentials.requires_scopes

    def test_with_scopes(self, app_engine):
        credentials = app_engine.Credentials()

        assert not credentials.scopes
        assert credentials.requires_scopes

        scoped_credentials = credentials.with_scopes(['email'])

        assert scoped_credentials.has_scopes(['email'])
        assert not scoped_credentials.requires_scopes

    @mock.patch(
        'google.auth._helpers.utcnow',
        return_value=datetime.datetime.min)
    def test_refresh(self, now_mock, app_engine, app_identity_mock):
        token = 'token'
        ttl = 100
        app_identity_mock.get_access_token.return_value = (token, ttl)
        credentials = app_engine.Credentials(scopes=['email'])

        credentials.refresh(None)

        app_identity_mock.get_access_token.assert_called_with(
            credentials.scopes, credentials._service_account_id)
        assert credentials.token == token
        assert credentials.expiry == (
            datetime.datetime.min + datetime.timedelta(seconds=ttl))
        assert credentials.valid
        assert not credentials.expired

    def test_refresh_failure(self, app_engine_no_apis):
        with pytest.raises(exceptions.RefreshError) as excinfo:
            app_engine_no_apis.Credentials().refresh(None)

        assert excinfo.match(r'App Engine APIs are not available')

    def test_sign_bytes(self, app_engine, app_identity_mock):
        app_identity_mock.sign_blob.return_value = mock.sentinel.signature
        credentials = app_engine.Credentials()
        to_sign = b'123'

        signature = credentials.sign_bytes(to_sign)

        assert signature == mock.sentinel.signature
        app_identity_mock.sign_blob.assert_called_with(to_sign)

    def test_sign_bytes_failure(self, app_engine_no_apis):
        with pytest.raises(EnvironmentError) as excinfo:
            app_engine_no_apis.Credentials().sign_bytes(b'123')

        assert excinfo.match(r'App Engine APIs are not available')
