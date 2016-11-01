# Copyright 2015 Google Inc.
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

"""Helpers for transitioning from oauth2client to google-auth."""

from __future__ import absolute_import

from google.auth import _helpers
import google.auth.app_engine
import google.oauth2.credentials
import google.oauth2.service_account

try:
    import oauth2client.client
    import oauth2client.contrib.gce
    import oauth2client.service_account
    _HAS_OAUTH2CLIENT = True
except ImportError:  # pragma: NO COVER
    _HAS_OAUTH2CLIENT = False

try:
    import oauth2client.contrib.appengine
    _HAS_APPENGINE = True
except ImportError:
    _HAS_APPENGINE = False


def _convert_oauth2_credentials(credentials):
    """Converts to :class:`google.oauth2.credentials.Credentials`."""
    new_credentials = google.oauth2.credentials.Credentials(
        token=credentials.access_token,
        refresh_token=credentials.refresh_token,
        token_uri=credentials.token_uri,
        client_id=credentials.client_id,
        client_secret=credentials.client_secret,
        scopes=credentials.scopes)

    new_credentials._expires = credentials.token_expiry

    return new_credentials


def _convert_service_account_credentials(credentials):
    """Converts to :class:`google.oauth2.service_account.Credentials`."""
    info = credentials.serialization_data
    info['token_uri'] = credentials.token_uri
    return google.oauth2.service_account.Credentials.from_service_account_info(
        info)


def _convert_gce_app_assertion_credentials(credentials):
    """Converts to :class:`google.auth.compute_engine.Credentials`."""
    return google.auth.compute_engine.Credentials(
        service_account_email=credentials.service_account_email)


def _convert_appengine_app_assertion_credentials(credentials):
    """Converts to :class:`google.auth.app_engine.Credentials`."""
    return google.auth.app_engine.Credentials(
        scopes=(_helpers.string_to_scopes(credentials.scope)
                if credentials.scope is not None else None),
        service_account_id=credentials.service_account_id)


_CLASS_CONVERSION_MAP = {}

if _HAS_OAUTH2CLIENT:
    _CLASS_CONVERSION_MAP.update({
        oauth2client.client.OAuth2Credentials: _convert_oauth2_credentials,
        oauth2client.client.GoogleCredentials: _convert_oauth2_credentials,
        oauth2client.service_account.ServiceAccountCredentials:
            _convert_service_account_credentials,
        oauth2client.service_account._JWTAccessCredentials:
            _convert_service_account_credentials,
        oauth2client.contrib.gce.AppAssertionCredentials:
            _convert_gce_app_assertion_credentials,
    })

if _HAS_APPENGINE:
    _CLASS_CONVERSION_MAP[
        oauth2client.contrib.appengine.AppAssertionCredentials] = (
            _convert_appengine_app_assertion_credentials)


def convert(credentials):
    """Convert oauth2client credentials to google-auth credentials.

    This class converts:

    - :class:`oauth2client.client.OAuth2Credentials` to
      :class:`google.oauth2.credentials.Credentials`.
    - :class:`oauth2client.client.GoogleCredentials` to
      :class:`google.oauth2.credentials.Credentials`.
    - :class:`oauth2client.service_account.ServiceAccountCredentials` to
      :class:`google.oauth2.service_account.Credentials`.
    - :class:`oauth2client.service_account._JWTAccessCredentials` to
      :class:`google.oauth2.service_account.Credentials`.
    - :class:`oauth2client.contrib.gce.AppAssertionCredentials` to
      :class:`google.auth.compute_engine.Credentials`.
    - :class:`oauth2client.contrib.appengine.AppAssertionCredentials` to
      :class:`google.auth.app_engine.Credentials`.

    Returns:
        google.auth.credentials.Credentials: The converted credentials.

    Raises:
        EnvironmentError: If oauth2client is not installed.
        ValueError: If the credentials could not be converted.
    """
    if not _HAS_OAUTH2CLIENT:
        raise EnvironmentError(
            'oauth2client is not installed and is required in order to convert'
            'credentials.')

    credentials_class = type(credentials)

    try:
        return _CLASS_CONVERSION_MAP[credentials_class](credentials)
    except KeyError:
        raise ValueError(
            'Unable to convert {} to a google-auth credentials class.'.format(
                credentials_class))
