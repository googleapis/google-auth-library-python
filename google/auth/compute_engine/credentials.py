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

"""Google Compute Engine credentials.

This module provides authentication for application running on Google Compute
Engine using the Compute Engine metadata server.
"""

from six.moves import http_client

from google.auth import credentials
from google.auth import exceptions
from google.auth.compute_engine import _metadata


class Credentials(credentials.Credentials,
                  credentials.ScopedCredentials):
    """Compute Engine Credentials.

    These credentials use the Google Compute Engine metadata server to obtain
    OAuth 2.0 access tokens associated with the instance's service account.

    .. note:: Compute Engine instances can be created with scopes and therefore
        these credentials are considered to be 'scoped'. However, you can
        not use :meth:`~google.auth.credentials.ScopedCredentials.with_scopes`
        because it is not possible to change the scopes that the instance
        has. Also note that
        :meth:`~google.auth.credentials.ScopedCredentials.has_scopes` will not
        work until the credentials have been refreshed.
    """

    def __init__(self, service_account_email='default'):
        """Constructor.

        Args:
            service_account_email (str): The service account email to use, or
                'default'. A Compute Engine instance may have multiple service
                accounts.
        """
        super(Credentials, self).__init__()
        self._service_account_email = service_account_email

    def _retrieve_info(self, http):
        """Retrieve information about the service account.

        Updates the scopes and retrieves the full service account email.

        Args:
            http (Any): an object to be used to make HTTP requests.
        """
        info = _metadata.get_service_account_info(
            http,
            service_account=self._service_account_email)

        self._service_account_email = info['email']
        # pylint: disable=attribute-defined-outside-init
        # (pylint doesn't recognize that this is defined in ScopedCredentials)
        self._scopes = info['scopes']

    def refresh(self, http):
        """Refresh the access token and scopes.

        Args:
            http (Any): The transport HTTP object.
        """
        try:
            self._retrieve_info(http)
            self.token, self.expiry = _metadata.get_service_account_token(
                self._service_account_email)
        except http_client.HTTPException as exc:
            raise exceptions.RefreshError(*exc.args)

    @property
    def requires_scopes(self):
        """False, Compute Engine credentials can not be scoped."""
        return False

    def with_scopes(self, scopes):
        """Unavailabe, Compute Engine credentials can not be scoped."""
        raise NotImplementedError(
            'Compute Engine credentials can not set scopes. Scopes must be '
            'set when the Compute Engine instance is created.')
