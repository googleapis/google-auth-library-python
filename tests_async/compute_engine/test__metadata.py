# Copyright 2020 Google LLC
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
import json
import os

import mock
import pytest
from six.moves import http_client
from six.moves import reload_module

from google.auth import _helpers
from google.auth import environment_vars
from google.auth import exceptions
from google.auth import transport
from google.auth.compute_engine import _metadata_async 

PATH = "instance/service-accounts/default"


def make_request(data, status=http_client.OK, headers=None, retry=False):
    response = mock.AsyncMock(spec=["transport.Response"])
    response.status = status

    response_data = _helpers.to_bytes(data)
    response.data = mock.AsyncMock(spec=["__call__", "read"])
    response.data.read = mock.AsyncMock(spec=["__call__"], return_value=response_data)
    response.headers = headers or {}

    request = mock.AsyncMock(spec=["transport.Request"])
    request.return_value = response

    return request

@pytest.mark.asyncio
async def test_ping_success():
    request = make_request("", headers=_metadata._METADATA_HEADERS)

    boolean = await _metadata_async.ping(request)
    assert boolean

    request.assert_called_once_with(
        method="GET",
        url=_metadata._METADATA_IP_ROOT,
        headers=_metadata._METADATA_HEADERS,
        timeout=_metadata._METADATA_DEFAULT_TIMEOUT,
    )


@pytest.mark.asyncio
async def test_ping_success_retry():
    request = make_request("", headers=_metadata_async._METADATA_HEADERS, retry=True)

    boolean = _metadata_async.ping(request)
    assert boolean

    request.assert_called_with(
        method="GET",
        url=_metadata._METADATA_IP_ROOT,
        headers=_metadata._METADATA_HEADERS,
        timeout=_metadata._METADATA_DEFAULT_TIMEOUT,
    )
    assert request.call_count == 2

@pytest.mark.asyncio
async def test_ping_failure_bad_flavor():
    request = make_request("", headers={_metadata._METADATA_FLAVOR_HEADER: "meep"})

    boolean = await _metadata_async.ping(request)
    assert not boolean

@pytest.mark.asyncio
async def test_ping_failure_connection_failed():
    request = make_request("")
    request.side_effect = exceptions.TransportError()

    boolean = await _metadata_async.ping(request)
    assert not boolean

@pytest.mark.asyncio
async def test_ping_success_custom_root():
    request = make_request("", headers=_metadata._METADATA_HEADERS)

    fake_ip = "1.2.3.4"
    os.environ[environment_vars.GCE_METADATA_IP] = fake_ip
    reload_module(_metadata)

    try:
        boolean = await _metadata_async.ping(request)
        assert not boolean
    finally:
        del os.environ[environment_vars.GCE_METADATA_IP]
        reload_module(_metadata)

    request.assert_called_once_with(
        method="GET",
        url="http://" + fake_ip,
        headers=_metadata._METADATA_HEADERS,
        timeout=_metadata._METADATA_DEFAULT_TIMEOUT,
    )

@pytest.mark.asyncio
async def test_get_success_json():
    key, value = "foo", "bar"

    data = json.dumps({key: value})
    request = make_request(data, headers={"content-type": "application/json"})

    result = await _metadata_async.get(request, PATH)

    request.assert_called_once_with(
        method="GET",
        url=_metadata._METADATA_ROOT + PATH,
        headers=_metadata._METADATA_HEADERS,
    )
    assert result[key] == value

@pytest.mark.asyncio
async def test_get_success_retry():
    key, value = "foo", "bar"

    data = json.dumps({key: value})
    request = make_request(
        data, headers={"content-type": "application/json"}, retry=True
    )

    result = await _metadata_async.get(request, PATH)

    request.assert_called_with(
        method="GET",
        url=_metadata._METADATA_ROOT + PATH,
        headers=_metadata._METADATA_HEADERS,
    )
    assert request.call_count == 2
    assert result[key] == value

@pytest.mark.asyncio
async def test_get_success_text():
    data = "foobar"
    request = make_request(data, headers={"content-type": "text/plain"})

    result = await _metadata_async.get(request, PATH)

    request.assert_called_once_with(
        method="GET",
        url=_metadata._METADATA_ROOT + PATH,
        headers=_metadata._METADATA_HEADERS,
    )
    assert result == data

@pytest.mark.asyncio
async def test_get_success_custom_root_new_variable():
    request = make_request("{}", headers={"content-type": "application/json"})

    fake_root = "another.metadata.service"
    os.environ[environment_vars.GCE_METADATA_HOST] = fake_root
    reload_module(_metadata)

    try:
        await _metadata_async.get(request, PATH)
    finally:
        del os.environ[environment_vars.GCE_METADATA_HOST]
        reload_module(_metadata)

    request.assert_called_once_with(
        method="GET",
        url="http://{}/computeMetadata/v1/{}".format(fake_root, PATH),
        headers=_metadata._METADATA_HEADERS,
    )

@pytest.mark.asyncio
async def test_get_success_custom_root_old_variable():
    request = make_request("{}", headers={"content-type": "application/json"})

    fake_root = "another.metadata.service"
    os.environ[environment_vars.GCE_METADATA_ROOT] = fake_root
    reload_module(_metadata)

    try:
        await _metadata_async.get(request, PATH)
    finally:
        del os.environ[environment_vars.GCE_METADATA_ROOT]
        reload_module(_metadata)

    request.assert_called_once_with(
        method="GET",
        url="http://{}/computeMetadata/v1/{}".format(fake_root, PATH),
        headers=_metadata._METADATA_HEADERS,
    )

@pytest.mark.asyncio
async def test_get_failure():
    request = make_request("Metadata error", status=http_client.NOT_FOUND)

    with pytest.raises(exceptions.TransportError) as excinfo:
        await _metadata_async.get(request, PATH)

    assert excinfo.match(r"Metadata error")

    request.assert_called_once_with(
        method="GET",
        url=_metadata._METADATA_ROOT + PATH,
        headers=_metadata._METADATA_HEADERS,
    )

@pytest.mark.asyncio
async def test_get_failure_connection_failed():
    request = make_request("")
    request.side_effect = exceptions.TransportError()

    with pytest.raises(exceptions.TransportError) as excinfo:
        await _metadata_async.get(request, PATH)

    assert excinfo.match(r"Compute Engine Metadata server unavailable")

    request.assert_called_with(
        method="GET",
        url=_metadata._METADATA_ROOT + PATH,
        headers=_metadata._METADATA_HEADERS,
    )
    assert request.call_count == 5

@pytest.mark.asyncio
async def test_get_failure_bad_json():
    request = make_request("{", headers={"content-type": "application/json"})

    with pytest.raises(exceptions.TransportError) as excinfo:
        await _metadata.get(request, PATH)

    assert excinfo.match(r"invalid JSON")

    request.assert_called_once_with(
        method="GET",
        url=_metadata._METADATA_ROOT + PATH,
        headers=_metadata._METADATA_HEADERS,
    )

@pytest.mark.asyncio
async def test_get_project_id():
    project = "example-project"
    request = make_request(project, headers={"content-type": "text/plain"})

    project_id = await _metadata.get_project_id(request)

    request.assert_called_once_with(
        method="GET",
        url=_metadata._METADATA_ROOT + "project/project-id",
        headers=_metadata._METADATA_HEADERS,
    )
    assert project_id == project


@mock.patch("google.auth._helpers.utcnow", return_value=datetime.datetime.min)
@pytest.mark.asyncio
async def test_get_service_account_token(utcnow):
    ttl = 500
    request = make_request(
        json.dumps({"access_token": "token", "expires_in": ttl}),
        headers={"content-type": "application/json"},
    )

    token, expiry = await _metadata_async.get_service_account_token(request)

    request.assert_called_once_with(
        method="GET",
        url=_metadata._METADATA_ROOT + PATH + "/token",
        headers=_metadata._METADATA_HEADERS,
    )
    assert token == "token"
    assert expiry == utcnow() + datetime.timedelta(seconds=ttl)

@pytest.mark.asyncio
async def test_get_service_account_info():
    key, value = "foo", "bar"
    request = make_request(
        json.dumps({key: value}), headers={"content-type": "application/json"}
    )

    info = await _metadata_async.get_service_account_info(request)

    request.assert_called_once_with(
        method="GET",
        url=_metadata._METADATA_ROOT + PATH + "/?recursive=true",
        headers=_metadata._METADATA_HEADERS,
    )

    assert info[key] == value
