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

"""Application default credentials.

Implements application default credentials and project ID detection.
"""

import io
import json
import os

from six.moves import configparser

from google.auth import compute_engine
from google.auth import exceptions
from google.auth.compute_engine import _metadata
import google.auth.transport._http_client
from google.oauth2 import service_account
import google.oauth2.credentials

# Environment variable for explicit application default credentials and project
# ID.
_CREDENTIALS_ENV = 'GOOGLE_APPLICATION_CREDENTIALS'
_PROJECT_ENV = 'GCLOUD_PROJECT'

# Valid types accepted for file-based credentials.
_AUTHORIZED_USER_TYPE = 'authorized_user'
_SERVICE_ACCOUNT_TYPE = 'service_account'
_VALID_TYPES = (_AUTHORIZED_USER_TYPE, _SERVICE_ACCOUNT_TYPE)

# The Google OAuth 2.0 token endpoint. Used for authorized user credentials.
_GOOGLE_OAUTH2_TOKEN_ENDPOINT = 'https://accounts.google.com/o/oauth2/token'

# The ~/.config subdirectory containing gcloud credentials.
_CLOUDSDK_CONFIG_DIRECTORY = 'gcloud'
# Windows systems store config at %APPDATA%\gcloud
_CLOUDSDK_WINDOWS_CONFIG_ROOT_ENV_VAR = 'APPDATA'
# The environment variable name which can replace ~/.config if set.
_CLOUDSDK_CONFIG_ENV = 'CLOUDSDK_CONFIG'
# The name of the file in the Cloud SDK config that contains default
# credentials.
_CLOUDSDK_CREDENTIALS_FILENAME = 'application_default_credentials.json'
# The name of the file in the Cloud SDK config that contains the
# active configuration.
_CLOUDSDK_ACTIVE_CONFIG_FILENAME = os.path.join(
    'configurations', 'config_default')
# The config section and key for the project ID in the cloud SDK config.
_CLOUDSDK_PROJECT_CONFIG_SECTION = 'core'
_CLOUDSDK_PROJECT_CONFIG_KEY = 'project'

# Help message when no credentials can be found.
_HELP_MESSAGE = (
    'Could not automatically determine credentials. Please set {env} or '
    'explicitly create credential and re-run the application. For more '
    'information, please see https://developers.google.com/accounts/docs'
    '/application-default-credentials.'.format(env=_CREDENTIALS_ENV))


def _load_credentials_from_file(filename):
    """Loads credentials from a file.

    The credentials file must be a service account key or stored authorized
    user credentials.

    Args:
        filename (str): The full path to the credentials file.

    Returns:
        Tuple[google.auth.credentials.Credentials, Optional[str]]: Loaded
            credentials and the project ID. Authorized user credentials do not
            have the project ID information.

    Raises:
        google.auth.exceptions.DefaultCredentialsError: if the file is in the
            wrong format.
    """
    with io.open(filename, 'r') as file_obj:
        try:
            info = json.load(file_obj)
        except ValueError as exc:
            raise exceptions.DefaultCredentialsError(
                'File {} is not a valid json file.'.format(filename), exc)

    # The type key should indicate that the file is either a service account
    # credentials file or an authorized user credentials file.
    credential_type = info.get('type')

    if credential_type == _AUTHORIZED_USER_TYPE:
        credentials = google.oauth2.credentials.Credentials(
            None,
            refresh_token=info['refresh_token'],
            token_uri=_GOOGLE_OAUTH2_TOKEN_ENDPOINT,
            client_id=info['client_id'],
            client_secret=info['client_secret'])
        # Authorized user credentials do not contain the project ID.
        return credentials, None

    elif credential_type == _SERVICE_ACCOUNT_TYPE:
        credentials = service_account.Credentials.from_service_account_info(
            info)
        return credentials, info.get('project_id')

    else:
        raise exceptions.DefaultCredentialsError(
            'The file {file} does not have a valid type. '
            'Type is {type}, expected one of {valid_types}.'.format(
                file=filename, type=credential_type, valid_types=_VALID_TYPES))


def _get_explicit_environ_credentials():
    """Gets credentials from the GOOGLE_APPLICATION_CREDENTIALS environment
    variable."""
    explicit_file = os.environ.get(_CREDENTIALS_ENV)
    if explicit_file is not None:
        return _load_credentials_from_file(os.environ[_CREDENTIALS_ENV])
    else:
        return None, None


def _get_gcloud_sdk_project_id(config_path):
    """Gets the project ID from the Cloud SDK's configuration.

    Args:
        config_path (str): The path to the Cloud SDK's config directory,
            for example ``~/.config/gcloud``.

    Returns:
        Optional[str]: The project ID.
    """
    config_file = os.path.join(config_path, _CLOUDSDK_ACTIVE_CONFIG_FILENAME)

    if not os.path.isfile(config_file):
        return None

    config = configparser.RawConfigParser()

    try:
        config.read(config_file)
    except configparser.Error:
        return None

    if config.has_section(_CLOUDSDK_PROJECT_CONFIG_SECTION):
        return config.get(
            _CLOUDSDK_PROJECT_CONFIG_SECTION, _CLOUDSDK_PROJECT_CONFIG_KEY)


def _get_gcloud_sdk_config_path():
    """Returns the absolute path the the Cloud SDK's configuration directory.

    Returns:
        str: The Cloud SDK config path.
    """
    # If the path is explicitly set, return that.
    try:
        return os.environ[_CLOUDSDK_CONFIG_ENV]
    except KeyError:
        pass

    # Non-windows systems store this at ~/.config/gcloud
    if os.name != 'nt':
        return os.path.join(
            os.path.expanduser('~'), '.config', _CLOUDSDK_CONFIG_DIRECTORY)
    # Windows systems store config at %APPDATA%\gcloud
    else:
        try:
            return os.path.join(
                os.environ[_CLOUDSDK_WINDOWS_CONFIG_ROOT_ENV_VAR],
                _CLOUDSDK_CONFIG_DIRECTORY)
        except KeyError:
            # This should never happen unless someone is really
            # messing with things, but we'll cover the case anyway.
            drive = os.environ.get('SystemDrive', 'C:')
            return os.path.join(
                drive, '\\', _CLOUDSDK_CONFIG_DIRECTORY)


def _get_gcloud_sdk_credentials():
    """Gets the credentials and project ID from the Cloud SDK."""
    # Get the Cloud SDK's configuration path.
    config_path = _get_gcloud_sdk_config_path()

    # Check the config path for the credentials file.
    credentials_filename = os.path.join(
        config_path, _CLOUDSDK_CREDENTIALS_FILENAME)

    if not os.path.isfile(credentials_filename):
        return None, None

    credentials, project_id = _load_credentials_from_file(
        credentials_filename)

    if not project_id:
        project_id = _get_gcloud_sdk_project_id(config_path)

    return credentials, project_id


def _get_gae_credentials():
    """Gets Google App Engine App Identity credentials and project ID."""
    return None, None


def _get_gce_credentials(request=None):
    """Gets credentials and project ID from the GCE Metadata Service."""
    # Ping requires a transport, but we want application default credentials
    # to require no arguments. So, we'll use the _http_client transport which
    # uses http.client. This is only acceptable because the metadata server
    # doesn't do SSL and never requires proxies.

    if request is None:
        request = google.auth.transport._http_client.Request()

    if _metadata.ping(request=request):
        # Get the project ID.
        try:
            project_id = _metadata.get(request, 'project/project-id')
        except exceptions.TransportError:
            project_id = None

        return compute_engine.Credentials(), project_id
    else:
        return None, None


def default(request=None):
    """Gets the default credentials for the current environment.

    `Application Default Credentials`_ provides an easy way to obtain
    credentials to call Google APIs for server-to-server or local applications.
    This function acquires credentials from the environment in the following
    order:

    1. If the environment variable ``GOOGLE_APPLICATION_CREDENTIALS`` is set
       to the path of a valid service account JSON private key file, then it is
       loaded and returned. The project ID returned is the project ID defined
       in the service account file if available (some older files do not
       contain project ID information).
    2. If the `Google Cloud SDK`_ is installed and has application default
       credentials set they are loaded and returned.

       To enable application default credentials with the Cloud SDK run::

            gcloud auth application-default login

       If the Cloud SDK has an active project, the project ID is returned. The
       active project can be set using::

            gcloud config set project

    3. If the application is running in the `App Engine standard environment`_
       then the credentials and project ID from the `App Identity Service`_
       are used.
    4. If the application is running in `Compute Engine`_ or the
       `App Engine flexible environment`_ then the credentials and project ID
       are obtained from the `Metadata Service`_.
    5. If no credentials are found,
       :class:`~google.auth.exceptions.DefaultCredentialsError` will be raised.

    .. _Application Default Credentials: https://developers.google.com\
            /identity/protocols/application-default-credentials
    .. _Google Cloud SDK: https://cloud.google.com/sdk
    .. _App Engine standard environment: https://cloud.google.com/appengine
    .. _App Identity Service: https://cloud.google.com/appengine/docs/python\
            /appidentity/
    .. _Compute Engine: https://cloud.google.com/compute
    .. _App Engine flexible environment: https://cloud.google.com\
            /appengine/flexible
    .. _Metadata Service: https://cloud.google.com/compute/docs\
            /storing-retrieving-metadata

    Example::

        import google.auth

        credentials, project_id = google.auth.default()

    Args:
        request (google.auth.transport.Request): An object used to make
            HTTP requests. This is used to detect whether the application
            is running on Compute Engine. If not specified, then it will
            use the standard library http client to make requests.

    Returns:
        Tuple[~google.auth.credentials.Credentials, Optional[str]]:
            the current environment's credentials and project ID. Project ID
            may be None, which indicates that the Project ID could not be
            ascertained from the environment.

    Raises:
        ~google.auth.exceptions.DefaultCredentialsError:
            If no credentials were found, or if the credentials found were
            invalid.
    """
    explicit_project_id = os.environ.get(_PROJECT_ENV)

    checkers = (
        _get_explicit_environ_credentials,
        _get_gcloud_sdk_credentials,
        _get_gae_credentials,
        lambda: _get_gce_credentials(request))

    for checker in checkers:
        credentials, project_id = checker()
        if credentials is not None:
            return credentials, explicit_project_id or project_id

    raise exceptions.DefaultCredentialsError(_HELP_MESSAGE)
