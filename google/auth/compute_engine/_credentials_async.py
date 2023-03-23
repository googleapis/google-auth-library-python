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

"""Google Compute Engine credentials.

This module provides authentication for an application running on Google
Compute Engine using the Compute Engine metadata server.

"""

import google.auth._credentials_async as credentials_async
from google.auth import exceptions
from google.auth.compute_engine import _metadata_async as _metadata
from google.auth.compute_engine import credentials as credentials_sync


class Credentials(
    credentials_sync.Credentials,
    credentials_async.Credentials,
    credentials_async.Scoped,
    credentials_async.CredentialsWithQuotaProject
):
    """Async Compute Engine Credentials.

    These credentials use the Google Compute Engine metadata server to obtain
    OAuth 2.0 access tokens associated with the instance's service account,
    and are also used for Cloud Run, Flex and App Engine (except for the Python
    2.7 runtime, which is supported only on older versions of this library).

    For more information about Compute Engine authentication, including how
    to configure scopes, see the `Compute Engine authentication
    documentation`_.

    .. note:: On Compute Engine the metadata server ignores requested scopes.
        On Cloud Run, Flex and App Engine the server honours requested scopes.

    .. _Compute Engine authentication documentation:
        https://cloud.google.com/compute/docs/authentication#using
    """

    def __init__(
        self,
        service_account_email="default",
        quota_project_id=None,
        scopes=None,
        default_scopes=None,
    ):
        """
        Args:
            service_account_email (str): The service account email to use, or
                'default'. A Compute Engine instance may have multiple service
                accounts.
            quota_project_id (Optional[str]): The project ID used for quota and
                billing.
            scopes (Optional[Sequence[str]]): The list of scopes for the credentials.
            default_scopes (Optional[Sequence[str]]): Default scopes passed by a
                Google client library. Use 'scopes' for user-defined scopes.
        """
        super(Credentials, self).__init__()
        self._service_account_email = service_account_email
        self._quota_project_id = quota_project_id
        self._scopes = scopes
        self._default_scopes = default_scopes

    async def _retrieve_info(self, request):
        """Retrieve information about the service account.

        Updates the scopes and retrieves the full service account email.

        Args:
            request (google.auth.transport.Request): The object used to make
                HTTP requests.
        """
        info = await _metadata.get_service_account_info(
            request, service_account=self._service_account_email
        )

        self._service_account_email = info["email"]

        # Don't override scopes requested by the user.
        if self._scopes is None:
            self._scopes = info["scopes"]

    async def refresh(self, request):
        """Refresh the access token and scopes.

        Args:
            request (google.auth.transport.Request): The object used to make
                HTTP requests.

        Raises:
            google.auth.exceptions.RefreshError: If the Compute Engine metadata
                service can't be reached or if the instance has no
                credentials.
        """
        scopes = self._scopes if self._scopes is not None else self._default_scopes
        try:
            await self._retrieve_info(request)
            self.token, self.expiry = await _metadata.get_service_account_token(
                request, service_account=self._service_account_email, scopes=scopes
            )
        except exceptions.TransportError as caught_exc:
            new_exc = exceptions.RefreshError(caught_exc)
            raise new_exc from caught_exc
