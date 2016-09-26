# Copyright 2016 Google Inc. All rights reserved.
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

from six.moves import http_client
from six.moves.urllib import parse as urlparse

from google.auth import _helpers
from google.auth import transport

_METADATA_ROOT = 'http://metadata.google.internal/computeMetadata/v1/'
_METADATA_HEADERS = {'Metadata-Flavor': 'Google'}


def get(http, path, root=_METADATA_ROOT, recursive=None):
    """Fetch a resource from the metadata server.

    Args:
        http (Any): The transport HTTP object.
        path (str): The resource to retrieve. For example,
            ``'instance/service-accounts/defualt'``.
        root (str): The full path to the metadata server root.
        recursive (bool): Whether to do a recursive query of metadata. See
            https://cloud.google.com/compute/docs/metadata#aggcontents for more
            details.

    Returns:
        Union[Mapping, str]: If the metadata server returns JSON, a mapping of
            the decoded JSON is return. Otherwise, the response content is
            returned as a string.

    Raises:
        http_client.HTTPException: if an error occurred while retrieving
            metadata.
    """
    url = urlparse.urljoin(root, path)
    url = _helpers.update_query(url, {'recursive': recursive})

    response = transport.request(http, url, headers=_METADATA_HEADERS)

    if response.status == http_client.OK:
        content = _helpers.from_bytes(response.data)
        if response.headers['content-type'] == 'application/json':
            return json.loads(content)
        else:
            return content
    else:
        raise http_client.HTTPException(
            'Failed to retrieve {} from the Google Compute Engine'
            'metadata service. Status: {} Response:\n{}'.format(
                url, response.status, response.data))


def get_service_account_info(http, service_account='default'):
    """Get information about a service account from the metadata server.

    Args:
        http (Any): The transport HTTP object.
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
        http_client.HTTPException: if an error occurred while retrieving
            metadata.
    """
    return get(
        http,
        'instance/service-accounts/{0}/'.format(service_account),
        recursive=True)


def get_service_account_token(http, service_account='default'):
    """Get the OAuth 2.0 access token for a service account.

    Args:
        http (Any): The transport HTTP object.
        service_account (str): The string 'default' or a service account email
            address. The determines which service account for which to acquire
            an access token.

    Returns:
        Union[str, datetime]: The access token and its expiration.

    Raises:
        http_client.HTTPException: if an error occurred while retrieving
            metadata.
    """
    token_json = get(
        http,
        'instance/service-accounts/{0}/token'.format(service_account))
    token_expiry = _helpers.now() + datetime.timedelta(
        seconds=token_json['expires_in'])
    return token_json['access_token'], token_expiry
