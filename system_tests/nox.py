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
"""


def session_service_account(session):
    session.virtualenv = False
    session.run('pytest', 'test_service_account.py')


def session_oauth2_credentials(session):
    session.virtualenv = False
    session.run('pytest', 'test_oauth2_credentials.py')


def session_compute_engine(session):
    session.virtualenv = False
    session.run('pytest', 'test_compute_engine.py')


def session_app_engine(session):
    session.virtualenv = False
    session.run('pytest', 'app_engine/test_app_engine.py')


def session_default(session):
    session.virtualenv = False
    session.run('pytest', 'test_default.py')
