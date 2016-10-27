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

"""Noxfile for automating system tests.

This file handles setting up environments needed by the system tests. This
separates the tests from their environment configuration.

See the `nox docs`_ for details on how this file works:

.. _nox docs: http://nox.readthedocs.io/en/latest/
"""

import os

from nox.command import Command
import py.path


HERE = os.path.dirname(__file__)
DATA_DIR = os.path.join(HERE, 'data')
SERVICE_ACCOUNT_FILE = os.path.join(DATA_DIR, 'service_account.json')
AUTHORIZED_USER_FILE = os.path.join(DATA_DIR, 'authorized_user.json')
CLOUD_SDK_CONFIG_ENV = 'CLOUDSDK_CONFIG'

# If set, this is where the environment setup will store the Cloud SDK.
# If unset, it will download the SDK to a temporary directory.
CLOUD_SDK_ROOT = os.environ.get('CLOUD_SDK_ROOT')
if CLOUD_SDK_ROOT:
    CLOUD_SDK_ROOT = py.path.local(CLOUD_SDK_ROOT)
    CLOUD_SDK_ROOT.ensure(dir=True)
if not CLOUD_SDK_ROOT:
    CLOUD_SDK_ROOT = py.path.local.mkdtemp()


# Helper functions


def prerun(*args, **kwargs):
    """Runs a command before the session."""
    kwargs.setdefault('silent', True)
    env = os.environ.copy()
    env.update(kwargs.pop('env', {}))
    Command(args, env=env, **kwargs).run()


# Cloud SDK helpers


def setup_cloud_sdk():
    """Downloads and installs the Google Cloud SDK."""

    # If the sdk already exists, we don't need to do anything else.
    if CLOUD_SDK_ROOT.join('google-cloud-sdk').exists():
        return

    tar_file = 'google-cloud-sdk.tar.gz'
    tar_path = CLOUD_SDK_ROOT.join(tar_file)

    # Download the release.
    prerun(
        'wget', 'https://dl.google.com/dl/cloudsdk/release/{}'.format(
            tar_file),
        '-O', str(tar_path))

    # Extract the release.
    prerun('tar', 'xzf', str(tar_path), '-C', str(CLOUD_SDK_ROOT))
    tar_path.remove()

    # Run the install script.
    prerun(
        str(CLOUD_SDK_ROOT.join('google-cloud-sdk', 'install.sh')),
        '--usage-reporting', 'false',
        '--path-update', 'false',
        '--command-completion', 'false',
        env={CLOUD_SDK_CONFIG_ENV: str(CLOUD_SDK_ROOT)})

    return CLOUD_SDK_ROOT


def gcloud(*args, **kwargs):
    """Calls the Cloud SDK CLI."""
    bin = str(CLOUD_SDK_ROOT.join('google-cloud-sdk', 'bin', 'gcloud'))
    env = {CLOUD_SDK_CONFIG_ENV: str(CLOUD_SDK_ROOT)}
    return prerun(bin, *args, env=env, **kwargs)


def configure_cloud_sdk(application_default_credentials, project=False):
    """Configures the Cloud SDK with the given application default
    credentials.

    If project is True, then a project will be set in the active config.
    If it is false, this will ensure no project is set.
    """

    if project:
        gcloud('config', 'set', 'project', 'example-project')
    else:
        gcloud('config', 'unset', 'project')

    # Copy the credentials file to the config root. This is needed because
    # unfortunately gcloud doesn't provide a clean way to tell it to use
    # a particular set of credentials. However, this does verify that gcloud
    # also considers the credentials valid by calling application-default
    # print-access-token
    dest = CLOUD_SDK_ROOT.join('application_default_credentials.json')
    dest.remove()
    py.path.local(application_default_credentials).copy(dest)

    gcloud('auth', 'application-default', 'print-access-token')


# Test sesssions


def session_service_account(session):
    session.virtualenv = False
    session.run('pytest', 'test_service_account.py')


def session_oauth2_credentials(session):
    session.virtualenv = False
    session.run('pytest', 'test_oauth2_credentials.py')


def session_default_explicit_service_account(session):
    session.virtualenv = False
    session.env['GOOGLE_APPLICATION_CREDENTIALS'] = SERVICE_ACCOUNT_FILE
    session.env['EXPECT_PROJECT_ID'] = '1'
    session.run('pytest', 'test_default.py')


def session_default_explicit_authorized_user(session):
    session.virtualenv = False
    session.env['GOOGLE_APPLICATION_CREDENTIALS'] = AUTHORIZED_USER_FILE
    session.run('pytest', 'test_default.py')


def session_default_explicit_authorized_user_explicit_project(session):
    session.virtualenv = False
    session.env['GOOGLE_APPLICATION_CREDENTIALS'] = AUTHORIZED_USER_FILE
    session.env['GOOGLE_CLOUD_PROJECT'] = 'example-project'
    session.env['EXPECT_PROJECT_ID'] = '1'
    session.run('pytest', 'test_default.py')


def session_default_cloud_sdk_service_account(session):
    session.virtualenv = False
    setup_cloud_sdk()
    configure_cloud_sdk(SERVICE_ACCOUNT_FILE)

    session.env[CLOUD_SDK_CONFIG_ENV] = str(CLOUD_SDK_ROOT)
    session.env['EXPECT_PROJECT_ID'] = '1'
    session.run('pytest', 'test_default.py')


def session_default_cloud_sdk_authorized_user(session):
    session.virtualenv = False
    setup_cloud_sdk()
    configure_cloud_sdk(AUTHORIZED_USER_FILE)

    session.env[CLOUD_SDK_CONFIG_ENV] = str(CLOUD_SDK_ROOT)
    session.run('pytest', '--pdb', 'test_default.py')


def session_default_cloud_sdk_authorized_user_configured_project(session):
    session.virtualenv = False
    setup_cloud_sdk()
    configure_cloud_sdk(AUTHORIZED_USER_FILE, project=True)

    session.env[CLOUD_SDK_CONFIG_ENV] = str(CLOUD_SDK_ROOT)
    session.env['EXPECT_PROJECT_ID'] = '1'
    session.run('pytest', 'test_default.py')


def session_compute_engine(session):
    session.virtualenv = False
    session.run('pytest', 'test_compute_engine.py')


def session_app_engine(session):
    session.virtualenv = False
    session.run('pytest', 'app_engine/test_app_engine.py')
