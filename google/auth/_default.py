# Copyright 2015 Google Inc. All rights reserved.
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

"""Application default credentials."""

import json
import os

from google.auth import compute_engine
from google.auth import exceptions
from google.auth import jwt
from google.auth.compute_engine import _metadata

# Environment variable for explicit application default credentials.
_CREDENTIALS_ENV = 'GOOGLE_APPLICATION_CREDENTIALS'

# Valid types accepted for file-based credentials.
_AUTHORIZED_USER_TYPE = 'authorized_user'
_SERVICE_ACCOUNT_TYPE = 'service_account'
_VALID_TYPES = (_AUTHORIZED_USER_TYPE, _SERVICE_ACCOUNT_TYPE)

# The ~/.config subdirectory containing gcloud credentials.
_CLOUDSDK_CONFIG_DIRECTORY = 'gcloud'
# The environment variable name which can replace ~/.config if set.
_CLOUDSDK_CONFIG_ENV = 'CLOUDSDK_CONFIG'
# The name of the file in the Cloud SDK config that contains default
# credentials.
_CLOUDSDK_CREDENTIALS_FILENAME = 'application_default_credentials.json'

# Help message when no credentials can be found.
_HELP_MESSAGE = (
    'Could not automatically determine credentials. Please set {env} and '
    're-run the application. For more information, please see '
    'https://developers.google.com/accounts/docs'
    '/application-default-credentials.'.format(env=_CREDENTIALS_ENV))


def _load_credentials_from_file(filename):
    with open(filename) as file_obj:
        try:
            info = json.load(file_obj)
        except ValueError as exc:
            raise exceptions.DefaultCredentialsError(
                'File {} is not a valid json file.'.format(filename), exc)

    # The type key should indicate that the file is either a service account
    # credentials file or an authorized user credentials file.
    credential_type = info.get('type')

    if credential_type == _AUTHORIZED_USER_TYPE:
        raise NotImplementedError(
            'Authorized user credentials are not yet implemented.')

    if credential_type == _SERVICE_ACCOUNT_TYPE:
        # TODO: This should actually be a weird polymorphic class that
        # is jwt.Credentials until create_scoped is called, then it becomes
        # service_account.Credentials.
        return jwt.Credentials.from_service_account_info(info)

    else:
        raise exceptions.DefaultCredentialsError(
            'The file {file} does not have a valid type. '
            'Type is {type}, expected one of {valid_types}.'.format(
                file=filename, type=credential_type, valid_types=_VALID_TYPES))


def _get_explicit_environ_credentials():
    explicit_file = os.environ.get(_CREDENTIALS_ENV)
    if explicit_file is not None:
        return _load_credentials_from_file(os.environ[_CREDENTIALS_ENV])


def _get_gcloud_sdk_credentials():
    # Get the Cloud SDK's configuration path.
    config_path = os.getenv(_CLOUDSDK_CONFIG_ENV)
    if config_path is None:
        if os.name == 'nt':
            if 'APPDATA' in os.environ:
                config_path = os.path.join(
                    os.environ['APPDATA'], _CLOUDSDK_CONFIG_DIRECTORY)
            else:
                # This should never happen unless someone is really
                # messing with things, but we'll cover the case anyway.
                drive = os.environ.get('SystemDrive', 'C:')
                config_path = os.path.join(
                    drive, '\\', _CLOUDSDK_CONFIG_DIRECTORY)
        else:
            config_path = os.path.join(
                os.path.expanduser('~'), '.config', _CLOUDSDK_CONFIG_DIRECTORY)

    # Check the config path for the credentials file.
    credentials_filename = os.path.join(
        config_path, _CLOUDSDK_CREDENTIALS_FILENAME)

    if os.path.exists(credentials_filename):
        return _load_credentials_from_file(credentials_filename)


def _get_gae_credentials():
    return None


def _get_gce_credentials():
    if _metadata.ping():
        return compute_engine.Credentials()


def default():
    """Gets the default credentials for the current environment.

    Returns:
        google.auth.credentials.Credentials: the current environment's
            credentials.

    Raises:
        google.auth.exceptions.DefaultCredentialsError:
            If no credentials were found, or if the credentials found were
            invalid.
    """
    checkers = (
        _get_explicit_environ_credentials,
        _get_gcloud_sdk_credentials,
        _get_gae_credentials,
        _get_gce_credentials)

    for checker in checkers:
        credentials = checker()
        if credentials is not None:
            return credentials

    raise exceptions.DefaultCredentialsError(_HELP_MESSAGE)
