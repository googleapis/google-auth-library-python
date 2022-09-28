# Copyright 2022 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import re

import pytest
from _pytest.capture import CaptureFixture

import authenticate_explicit_with_adc
import authenticate_implicit_with_adc
import authenticate_with_api_key
import create_api_key
import delete_api_key
import idtoken_from_metadata_server
import idtoken_from_service_account
import lookup_api_key
# from system_tests.noxfile import SERVICE_ACCOUNT_FILE
import verify_google_idtoken

import google
from google.cloud.api_keys_v2 import Key
from google.oauth2 import service_account
import google.auth.transport.requests
import os

CREDENTIALS, PROJECT = google.auth.default()
SERVICE_ACCOUNT_FILE = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")


@pytest.fixture(scope="module")
def api_key():
    api_key = create_api_key.create_api_key(PROJECT, "global")
    yield api_key
    delete_api_key.delete_api_key(PROJECT, "global", api_key.name.rsplit("/")[-1])


def test_authenticate_explicit_with_adc(capsys: CaptureFixture):
    authenticate_explicit_with_adc.authenticate_explicit_with_adc()
    out, err = capsys.readouterr()
    assert re.search("Listed all storage buckets.", out)


def test_authenticate_implicit_with_adc(capsys: CaptureFixture):
    authenticate_implicit_with_adc.authenticate_implicit_with_adc(PROJECT)
    out, err = capsys.readouterr()
    assert re.search("Listed all storage buckets.", out)


def test_idtoken_from_metadata_server(capsys: CaptureFixture):
    idtoken_from_metadata_server.idtoken_from_metadata_server("https://www.google.com")
    out, err = capsys.readouterr()
    assert re.search("Generated ID token.", out)


def test_idtoken_from_service_account(capsys: CaptureFixture):
    idtoken_from_service_account.get_idToken_from_serviceaccount(
        SERVICE_ACCOUNT_FILE,
        "iap.googleapis.com")
    out, err = capsys.readouterr()
    assert re.search("Generated ID token.", out)


def test_verify_google_idtoken():
    idtoken = get_idtoken_from_service_account(SERVICE_ACCOUNT_FILE, "iap.googleapis.com")

    verify_google_idtoken.verify_google_idtoken(
        idtoken,
        "iap.googleapis.com",
        "https://www.googleapis.com/oauth2/v3/certs"
    )


def test_authenticate_with_api_key(api_key: Key, capsys: CaptureFixture):
    authenticate_with_api_key.authenticate_with_api_key(PROJECT, api_key.key_string)
    out, err = capsys.readouterr()
    assert re.search("Successfully authenticated using the API key", out)


def test_lookup_api_key(api_key: Key, capsys: CaptureFixture):
    lookup_api_key.lookup_api_key(api_key.key_string)
    out, err = capsys.readouterr()
    assert re.search(f"Successfully retrieved the API key name: {api_key.name}", out)


def get_idtoken_from_service_account(json_credential_path: str, target_audience: str):
    credentials = service_account.IDTokenCredentials.from_service_account_file(
        filename=json_credential_path,
        target_audience=target_audience)

    request = google.auth.transport.requests.Request()
    credentials.refresh(request)
    return credentials.token
