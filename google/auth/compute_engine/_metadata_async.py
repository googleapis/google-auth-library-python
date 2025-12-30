# Copyright 2023 Google LLC
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

"""Provides helper methods for talking to the Compute Engine metadata server.

See https://cloud.google.com/compute/docs/metadata for more details.
"""

import datetime
import json
import logging
import os
from http import HTTPStatus
from urllib.parse import urljoin

from google.auth import _helpers
from google.auth import environment_vars
from google.auth import exceptions
from google.auth import transport
from google.auth._exponential_backoff import ExponentialBackoff

_LOGGER = logging.getLogger(__name__)

# Environment variable GCE_METADATA_HOST is originally named
# GCE_METADATA_ROOT. For compatiblity reasons, here it checks
# the new variable first; if not set, the system falls back
# to the old variable.
_GCE_METADATA_HOST = os.getenv(environment_vars.GCE_METADATA_HOST, None)
if not _GCE_METADATA_HOST:
    _GCE_METADATA_HOST = os.getenv(
        environment_vars.GCE_METADATA_ROOT, "metadata.google.internal"
    )
_METADATA_ROOT = "http://{}/computeMetadata/v1/".format(_GCE_METADATA_HOST)

# This is used to ping the metadata server, it avoids the cost of a DNS
# lookup.
_METADATA_IP_ROOT = "http://{}".format(
    os.getenv(environment_vars.GCE_METADATA_IP, "169.254.169.254")
)
_METADATA_FLAVOR_HEADER = "metadata-flavor"
_METADATA_FLAVOR_VALUE = "Google"
_METADATA_HEADERS = {_METADATA_FLAVOR_HEADER: _METADATA_FLAVOR_VALUE}

# Timeout in seconds to wait for the GCE metadata server when detecting the
# GCE environment.
try:
    _METADATA_DEFAULT_TIMEOUT = int(os.getenv("GCE_METADATA_TIMEOUT", 3))
except ValueError:  # pragma: NO COVER
    _METADATA_DEFAULT_TIMEOUT = 3


async def ping(request, timeout=_METADATA_DEFAULT_TIMEOUT, retry_count=3):
    """Checks to see if the metadata server is available.

    Args:
        request (Callable): A callable used to make HTTP requests.
        timeout (int): How long to wait for the metadata server to respond.
        retry_count (int): How many times to attempt connecting to metadata
            server using above timeout.

    Returns:
        bool: True if the metadata server is reachable, False otherwise.
    """
    # NOTE: The explicit ``timeout`` is a workaround. The underlying
    #       issue is that resolving an unknown host on some networks will take
    #       20-30 seconds; making this timeout short fixes the issue, but
    #       could lead to false negatives in the event that we are on GCE, but
    #       the metadata resolution was particularly slow. The latter case is
    #       "unlikely".
    retries = 0
    while retries < retry_count:
        try:
            response = await request(
                url=_METADATA_IP_ROOT,
                method="GET",
                headers=_METADATA_HEADERS,
                timeout=timeout,
            )

            metadata_flavor = response.headers.get(_METADATA_FLAVOR_HEADER)
            return (
                response.status == HTTPStatus.OK
                and metadata_flavor == _METADATA_FLAVOR_VALUE
            )

        except exceptions.TransportError as e:
            _LOGGER.warning(
                "Compute Engine Metadata server unavailable on "
                "attempt %s of %s. Reason: %s",
                retries + 1,
                retry_count,
                e,
            )
            retries += 1

    return False


async def get(
    request, path, root=_METADATA_ROOT, params=None, recursive=False, retry_count=5
):
    """Fetch a resource from the metadata server.

    Args:
        request (Callable): A callable used to make HTTP requests.
        path (str): The resource to retrieve. For example,
            ``'instance/service-accounts/default'``.
        root (str): The full path to the metadata server root.
        params (Optional[Mapping[str, str]]): A mapping of query parameter
            keys to values.
        recursive (bool): Whether to do a recursive query of metadata. See
            https://cloud.google.com/compute/docs/metadata#aggcontents for more
            details.
        retry_count (int): How many times to attempt connecting to metadata
            server using above timeout.

    Returns:
        Union[Mapping, str]: If the metadata server returns JSON, a mapping of
            the decoded JSON is return. Otherwise, the response content is
            returned as a string.

    Raises:
        google.auth.exceptions.TransportError: if an error occurred while
            retrieving metadata.
    """
    base_url = urljoin(root, path)
    query_params = {} if params is None else params

    if recursive:
        query_params["recursive"] = "true"

    url = _helpers.update_query(base_url, query_params)

    backoff = ExponentialBackoff(total_attempts=retry_count)
    last_exception = None

    for attempt in backoff:
        try:
            response = await request(
                url=url, method="GET", headers=_METADATA_HEADERS
            )
            if response.status == HTTPStatus.OK:
                break

            if response.status in transport.DEFAULT_RETRYABLE_STATUS_CODES:
                 _LOGGER.warning(
                    "Compute Engine Metadata server unavailable on "
                    "attempt %s of %s. Response status: %s",
                    attempt,
                    retry_count,
                    response.status,
                )
                 continue
            else:
                break

        except exceptions.TransportError as e:
            _LOGGER.warning(
                "Compute Engine Metadata server unavailable on "
                "attempt %s of %s. Reason: %s",
                attempt,
                retry_count,
                e,
            )
            last_exception = e
            continue

    else:
        # Loop finished without break (all retries failed)
        if last_exception:
            raise exceptions.TransportError(
                "Failed to retrieve {} from the Google Compute Engine "
                "metadata service. Compute Engine Metadata server unavailable".format(url)
            ) from last_exception
        else:
             raise exceptions.TransportError(
                "Failed to retrieve {} from the Google Compute Engine "
                "metadata service. Compute Engine Metadata server unavailable.".format(url)
            )

    if response.status == HTTPStatus.OK:
        if hasattr(response.data, "read"):
            content = await response.data.read()
        else:
            content = response.data
        content = _helpers.from_bytes(content)

        if response.headers.get("content-type") == "application/json":
            try:
                return json.loads(content)
            except ValueError as caught_exc:
                new_exc = exceptions.TransportError(
                    "Received invalid JSON from the Google Compute Engine "
                    "metadata service: {:.20}".format(content)
                )
                raise new_exc from caught_exc
        else:
            return content
    else:
        raise exceptions.TransportError(
            "Failed to retrieve {} from the Google Compute Engine "
            "metadata service. Status: {} Response:\n{}".format(
                url, response.status, response.data
            ),
            response,
        )


async def get_project_id(request):
    """Get the Google Cloud Project ID from the metadata server.

    Args:
        request (Callable): A callable used to make HTTP requests.

    Returns:
        str: The project ID

    Raises:
        google.auth.exceptions.TransportError: if an error occurred while
            retrieving metadata.
    """
    return await get(request, "project/project-id")


async def get_service_account_info(request, service_account="default"):
    """Get information about a service account from the metadata server.

    Args:
        request (Callable): A callable used to make HTTP requests.
        service_account (str): The string 'default' or a service account email
            address. The determines which service account for which to acquire
            information.

    Returns:
        Mapping: The service account's information, for example::

            {
                'email': '...',
                'scopes': ['scope', ...],
                'aliases': ['default', '...']
            }

    Raises:
        google.auth.exceptions.TransportError: if an error occurred while
            retrieving metadata.
    """
    path = "instance/service-accounts/{0}/".format(service_account)
    # See https://cloud.google.com/compute/docs/metadata#aggcontents
    # for more on the use of 'recursive'.
    return await get(request, path, params={"recursive": "true"})


async def get_service_account_token(request, service_account="default", scopes=None):
    """Get the OAuth 2.0 access token for a service account.

    Args:
        request (Callable): A callable used to make HTTP requests.
        service_account (str): The string 'default' or a service account email
            address. The determines which service account for which to acquire
            an access token.
        scopes (Optional[Union[str, List[str]]]): Optional string or list of
            strings with auth scopes.
    Returns:
        Tuple[str, datetime]: The access token and its expiration.

    Raises:
        google.auth.exceptions.TransportError: if an error occurred while
            retrieving metadata.
    """
    if scopes:
        if not isinstance(scopes, str):
            scopes = ",".join(scopes)
        params = {"scopes": scopes}
    else:
        params = None

    path = "instance/service-accounts/{0}/token".format(service_account)
    token_json = await get(request, path, params=params)
    token_expiry = _helpers.utcnow() + datetime.timedelta(
        seconds=token_json["expires_in"]
    )
    return token_json["access_token"], token_expiry
