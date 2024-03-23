# Copyright 2016 Google LLC
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

import copy
import datetime
import json

import mock
import pytest  # type: ignore

from google.auth import _helpers
from google.auth import credentials
from google.auth import exceptions


class CredentialsImpl(credentials.Credentials):
    def refresh(self, request):
        self.token = request
        self.expiry = (
            datetime.datetime.utcnow()
            + _helpers.REFRESH_THRESHOLD
            + datetime.timedelta(seconds=5)
        )

    def with_quota_project(self, quota_project_id):
        raise NotImplementedError()


class CredentialsImplWithMetrics(credentials.Credentials):
    def refresh(self, request):
        self.token = request

    def _metric_header_for_usage(self):
        return "foo"


class CredentialsWithTrustBoundaryImpl(credentials.CredentialsWithTrustBoundary):
    def refresh(self, request):
        self.token = request


def test_credentials_constructor():
    credentials = CredentialsImpl()
    assert not credentials.token
    assert not credentials.expiry
    assert not credentials.expired
    assert not credentials.valid
    assert credentials.universe_domain == "googleapis.com"
    assert not credentials._use_non_blocking_refresh


def test_with_non_blocking_refresh():
    c = CredentialsImpl()
    c.with_non_blocking_refresh()
    assert c._use_non_blocking_refresh


def test_expired_and_valid():
    credentials = CredentialsImpl()
    credentials.token = "token"

    assert credentials.valid
    assert not credentials.expired

    # Set the expiration to one second more than now plus the clock skew
    # accomodation. These credentials should be valid.
    credentials.expiry = (
        _helpers.utcnow() + _helpers.REFRESH_THRESHOLD + datetime.timedelta(seconds=1)
    )

    assert credentials.valid
    assert not credentials.expired

    # Set the credentials expiration to now. Because of the clock skew
    # accomodation, these credentials should report as expired.
    credentials.expiry = _helpers.utcnow()

    assert not credentials.valid
    assert credentials.expired


def test_before_request():
    credentials = CredentialsImpl()
    request = "token"
    headers = {}

    # First call should call refresh, setting the token.
    credentials.before_request(request, "http://example.com", "GET", headers)
    assert credentials.valid
    assert credentials.token == "token"
    assert headers["authorization"] == "Bearer token"
    assert "x-allowed-locations" not in headers

    request = "token2"
    headers = {}

    # Second call shouldn't call refresh.
    credentials.before_request(request, "http://example.com", "GET", headers)
    assert credentials.valid
    assert credentials.token == "token"
    assert headers["authorization"] == "Bearer token"
    assert "x-allowed-locations" not in headers


def test_before_request_with_trust_boundary():
    credentials = CredentialsWithTrustBoundaryImpl()
    request = "token"
    headers = {}
    test_trust_boundary = {"locations": [], "encoded_locations": "0x30"}

    credentials.before_request(request, "http://example.com", "GET", headers)
    assert credentials.valid
    assert credentials.token == "token"
    assert headers["authorization"] == "Bearer token"
    assert "x-allowed-locations" not in headers

    credentials.trust_boundary = copy.deepcopy(test_trust_boundary)
    credentials.before_request(request, "http://example.com", "GET", headers)
    assert credentials.valid
    assert credentials.valid
    assert credentials.token == "token"
    assert headers["authorization"] == "Bearer token"
    assert headers["x-allowed-locations"] == test_trust_boundary["encoded_locations"]


def test_before_request_metrics():
    credentials = CredentialsImplWithMetrics()
    request = "token"
    headers = {}

    credentials.before_request(request, "http://example.com", "GET", headers)
    assert headers["x-goog-api-client"] == "foo"


def test_anonymous_credentials_ctor():
    anon = credentials.AnonymousCredentials()
    assert anon.token is None
    assert anon.expiry is None
    assert not anon.expired
    assert anon.valid


def test_anonymous_credentials_refresh():
    anon = credentials.AnonymousCredentials()
    request = object()
    with pytest.raises(ValueError):
        anon.refresh(request)


def test_anonymous_credentials_apply_default():
    anon = credentials.AnonymousCredentials()
    headers = {}
    anon.apply(headers)
    assert headers == {}
    with pytest.raises(ValueError):
        anon.apply(headers, token="TOKEN")


def test_anonymous_credentials_before_request():
    anon = credentials.AnonymousCredentials()
    request = object()
    method = "GET"
    url = "https://example.com/api/endpoint"
    headers = {}
    anon.before_request(request, method, url, headers)
    assert headers == {}


class ReadOnlyScopedCredentialsImpl(credentials.ReadOnlyScoped, CredentialsImpl):
    @property
    def requires_scopes(self):
        return super(ReadOnlyScopedCredentialsImpl, self).requires_scopes


def test_readonly_scoped_credentials_constructor():
    credentials = ReadOnlyScopedCredentialsImpl()
    assert credentials._scopes is None


def test_readonly_scoped_credentials_scopes():
    credentials = ReadOnlyScopedCredentialsImpl()
    credentials._scopes = ["one", "two"]
    assert credentials.scopes == ["one", "two"]
    assert credentials.has_scopes(["one"])
    assert credentials.has_scopes(["two"])
    assert credentials.has_scopes(["one", "two"])
    assert not credentials.has_scopes(["three"])


def test_readonly_scoped_credentials_requires_scopes():
    credentials = ReadOnlyScopedCredentialsImpl()
    assert not credentials.requires_scopes


class RequiresScopedCredentialsImpl(credentials.Scoped, CredentialsImpl):
    def __init__(self, scopes=None, default_scopes=None):
        super(RequiresScopedCredentialsImpl, self).__init__()
        self._scopes = scopes
        self._default_scopes = default_scopes

    @property
    def requires_scopes(self):
        return not self.scopes

    def with_scopes(self, scopes, default_scopes=None):
        return RequiresScopedCredentialsImpl(
            scopes=scopes, default_scopes=default_scopes
        )


def test_create_scoped_if_required_scoped():
    unscoped_credentials = RequiresScopedCredentialsImpl()
    scoped_credentials = credentials.with_scopes_if_required(
        unscoped_credentials, ["one", "two"]
    )

    assert scoped_credentials is not unscoped_credentials
    assert not scoped_credentials.requires_scopes
    assert scoped_credentials.has_scopes(["one", "two"])


def test_create_scoped_if_required_not_scopes():
    unscoped_credentials = CredentialsImpl()
    scoped_credentials = credentials.with_scopes_if_required(
        unscoped_credentials, ["one", "two"]
    )

    assert scoped_credentials is unscoped_credentials


def test_nonblocking_refresh_fresh_credentials():
    c = CredentialsImpl()

    c._refresh_worker = mock.MagicMock()

    request = "token"

    c.refresh(request)
    assert c.token_state == credentials.TokenState.FRESH

    c.with_non_blocking_refresh()
    c.before_request(request, "http://example.com", "GET", {})


def test_nonblocking_refresh_invalid_credentials():
    c = CredentialsImpl()
    c.with_non_blocking_refresh()

    request = "token"
    headers = {}

    assert c.token_state == credentials.TokenState.INVALID

    c.before_request(request, "http://example.com", "GET", headers)
    assert c.token_state == credentials.TokenState.FRESH
    assert c.valid
    assert c.token == "token"
    assert headers["authorization"] == "Bearer token"
    assert "x-identity-trust-boundary" not in headers


def test_nonblocking_refresh_stale_credentials():
    c = CredentialsImpl()
    c.with_non_blocking_refresh()

    request = "token"
    headers = {}

    # Invalid credentials MUST require a blocking refresh.
    c.before_request(request, "http://example.com", "GET", headers)
    assert c.token_state == credentials.TokenState.FRESH
    assert not c._refresh_worker._worker

    c.expiry = (
        datetime.datetime.utcnow()
        + _helpers.REFRESH_THRESHOLD
        - datetime.timedelta(seconds=1)
    )

    # STALE credentials SHOULD spawn a non-blocking worker
    assert c.token_state == credentials.TokenState.STALE
    c.before_request(request, "http://example.com", "GET", headers)
    assert c._refresh_worker._worker is not None

    assert c.token_state == credentials.TokenState.FRESH
    assert c.valid
    assert c.token == "token"
    assert headers["authorization"] == "Bearer token"
    assert "x-identity-trust-boundary" not in headers


def test_nonblocking_refresh_failed_credentials():
    c = CredentialsImpl()
    c.with_non_blocking_refresh()

    request = "token"
    headers = {}

    # Invalid credentials MUST require a blocking refresh.
    c.before_request(request, "http://example.com", "GET", headers)
    assert c.token_state == credentials.TokenState.FRESH
    assert not c._refresh_worker._worker

    c.expiry = (
        datetime.datetime.utcnow()
        + _helpers.REFRESH_THRESHOLD
        - datetime.timedelta(seconds=1)
    )

    # STALE credentials SHOULD spawn a non-blocking worker
    assert c.token_state == credentials.TokenState.STALE
    c._refresh_worker._worker = mock.MagicMock()
    c._refresh_worker._worker._error_info = "Some Error"
    c.before_request(request, "http://example.com", "GET", headers)
    assert c._refresh_worker._worker is not None

    assert c.token_state == credentials.TokenState.FRESH
    assert c.valid
    assert c.token == "token"
    assert headers["authorization"] == "Bearer token"
    assert "x-identity-trust-boundary" not in headers


def test_token_state_no_expiry():
    c = CredentialsImpl()

    request = "token"
    c.refresh(request)

    c.expiry = None
    assert c.token_state == credentials.TokenState.FRESH

    c.before_request(request, "http://example.com", "GET", {})


def test_credentials_with_trust_boundary_lookup():
    c = CredentialsWithTrustBoundaryImpl()
    assert c._lookup_trust_boundary(None) == credentials.DEFAULT_TRUST_BOUNDARY


@pytest.mark.parametrize(
    "test_data",
    [
        {
            "name": "valid payload",
            "expect_trust_boundary": {
                "locations": ["us-central1", "us-east1", "europe-west1", "asia-east1"],
                "encoded_locations": "0xA30",
            },
            "trust_boundary_string": json.dumps(
                {
                    "locations": [
                        "us-central1",
                        "us-east1",
                        "europe-west1",
                        "asia-east1",
                    ],
                    "encoded_locations": "0xA30",
                }
            ),
        },
        {
            "name": "missing fields",
            "trust_boundary_string": json.dumps({}),
            "expect_error": exceptions.MalformedError,
        },
        {
            "name": "invalid payload",
            "trust_boundary_string": "afwewfwe",
            "expect_error": exceptions.MalformedError,
        },
    ],
)
def test_parse_trust_boundary(test_data):
    if not test_data.get("expect_error"):
        assert test_data[
            "expect_trust_boundary"
        ] == credentials.CredentialsWithTrustBoundary.parse_trust_boundary(
            test_data["trust_boundary_string"]
        )
    else:
        with pytest.raises(test_data["expect_error"]):
            credentials.CredentialsWithTrustBoundary.parse_trust_boundary(
                test_data["trust_boundary_string"]
            )
