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

"""Google Compute Engine credentials.

This module provides authentication for application running on Google Compute
Engine using the Compute Engine metadata server.

"""

import six

from google.auth import _helpers
from google.auth import credentials
from google.auth import exceptions
from google.auth import iam
from google.auth.compute_engine import _metadata


class Credentials(credentials.ReadOnlyScoped, credentials.Credentials):
    """Compute Engine Credentials.

    These credentials use the Google Compute Engine metadata server to obtain
    OAuth 2.0 access tokens associated with the instance's service account.

    For more information about Compute Engine authentication, including how
    to configure scopes, see the `Compute Engine authentication
    documentation`_.

    .. note:: Compute Engine instances can be created with scopes and therefore
        these credentials are considered to be 'scoped'. However, you can
        not use :meth:`~google.auth.credentials.ScopedCredentials.with_scopes`
        because it is not possible to change the scopes that the instance
        has. Also note that
        :meth:`~google.auth.credentials.ScopedCredentials.has_scopes` will not
        work until the credentials have been refreshed.

    .. _Compute Engine authentication documentation:
        https://cloud.google.com/compute/docs/authentication#using
    """

    def __init__(self, service_account_email='default'):
        """
        Args:
            service_account_email (str): The service account email to use, or
                'default'. A Compute Engine instance may have multiple service
                accounts.
        """
        super(Credentials, self).__init__()
        self._service_account_email = service_account_email

    def _retrieve_info(self, request):
        """Retrieve information about the service account.

        Updates the scopes and retrieves the full service account email.

        Args:
            request (google.auth.transport.Request): The object used to make
                HTTP requests.
        """
        info = _metadata.get_service_account_info(
            request,
            service_account=self._service_account_email)

        self._service_account_email = info['email']
        self._scopes = info['scopes']

    def refresh(self, request):
        """Refresh the access token and scopes.

        Args:
            request (google.auth.transport.Request): The object used to make
                HTTP requests.

        Raises:
            google.auth.exceptions.RefreshError: If the Compute Engine metadata
                service can't be reached if if the instance has not
                credentials.
        """
        try:
            self._retrieve_info(request)
            self.token, self.expiry = _metadata.get_service_account_token(
                request,
                service_account=self._service_account_email)
        except exceptions.TransportError as caught_exc:
            new_exc = exceptions.RefreshError(caught_exc)
            six.raise_from(new_exc, caught_exc)

    @property
    def service_account_email(self):
        """The service account email.

        .. note: This is not guaranteed to be set until :meth`refresh` has been
            called.
        """
        return self._service_account_email

    @property
    def requires_scopes(self):
        """False: Compute Engine credentials can not be scoped."""
        return False


_DEFAULT_TOKEN_LIFETIME_SECS = 3600  # 1 hour in seconds
_DEFAULT_TOKEN_URI = 'https://www.googleapis.com/oauth2/v4/token'


class IDTokenCredentials(credentials.Credentials, credentials.Signing):
    """Open ID Connect ID Token-based service account credentials.

    These credentials relies on the default service account and metadata
    server of a GCE instance.

    The ID Token provided by this credential is provideb by the Compute
    metadata server service account.  For more information about the ID,
    see `Obtaining the instance identity token`_.

    In order to use the signer or sign_bytes capability directly, the GCE
    instance must have been started with a service account that has access
    to the IAM Cloud API and specifically the service account must be granted
    the `roles/iam.serviceAccountTokenCreator` role.  For more information on
    IAM roles, see `Understanding Roles`_.

    NOTE:  The ID Token is provided by the Metadata server and does _not_
    require this IAM role since the token is provided directly by the metadata
    server.  If you do need to `Singer` capability with this credential type,
    consider using :class:`~google.auth.impersonated_credentials` instead
    since signing bytes directly with
    :class:`compute_engine.IDTokenCredentials` internally should not be
    exposed.

    .. _Obtaining the instance identity token:
        https://cloud.google.com/compute/docs/instances/verifying-instance-identity#request_signature
    .. _Understanding Roles:
        https://cloud.google.com/iam/docs/understanding-roles#service-accounts-roles
    """
    def __init__(self, request, target_audience,
                 token_uri=_DEFAULT_TOKEN_URI,
                 additional_claims=None,
                 service_account_email=None,
                 token_format='standard',
                 include_license=False):
        """
        Args:
            request (google.auth.transport.Request): The object used to make
                HTTP requests.
            target_audience (str): The intended audience for these credentials,
                used when requesting the ID Token. The ID Token's ``aud`` claim
                will be set to this string.
            token_uri (str): The OAuth 2.0 Token URI.
            additional_claims (Mapping[str, str]): Unused.
            service_account_email (str): Optional explicit service account to
                sign with.  For id tokens, this must be set to `default` or
                to the service account the VM runs as.
            token_format (str): ID Token format to return with the request.
                Valid options are 'standard' or 'full'.
            include_license (bool):  Flag to include the license information
                within the ID Token.  Using this flag will automatically enable
                full token_format.
        """
        super(IDTokenCredentials, self).__init__()

        if service_account_email is None:
            sa_info = _metadata.get_service_account_info(request)
            service_account_email = sa_info['email']
        self._service_account_email = service_account_email

        self._signer = iam.Signer(
            request=request,
            credentials=Credentials(),
            service_account_email=service_account_email)

        self._token_uri = token_uri
        self._target_audience = target_audience
        self._request = request

        if additional_claims is not None:
            self._additional_claims = additional_claims
        else:
            self._additional_claims = {}

        self._include_license = include_license
        self._token_format = token_format
        if include_license:
            self._token_format = 'full'

    def with_target_audience(self, audience):
        """Create a copy of these credentials with the specified target
        audience.
        Args:
            audience (str): The intended audience for these credentials,
            used when requesting the ID Token.
        Returns:
            google.auth.service_account.IDTokenCredentials: A new credentials
                instance.
        """
        return self.__class__(
            request=self._request,
            service_account_email=self._service_account_email,
            token_uri=self._token_uri,
            additional_claims=self._additional_claims.copy(),
            token_format=self._token_format,
            include_license=self._include_license,
            target_audience=audience)

    @_helpers.copy_docstring(credentials.Credentials)
    def refresh(self, request):
        id_token, expiry = _metadata.get_id_token(
            request,
            self._service_account_email, self._target_audience,
            self._token_format, self._include_license)
        self.token = id_token
        self.expiry = expiry

    @property
    @_helpers.copy_docstring(credentials.Signing)
    def signer(self):
        return self._signer

    @_helpers.copy_docstring(credentials.Signing)
    def sign_bytes(self, message):
        return self._signer.sign(message)

    @property
    def service_account_email(self):
        """The service account email."""
        return self._service_account_email

    @property
    def signer_email(self):
        return self._service_account_email

    def with_token_format(self, token_format):
        """Create a copy of these credentials but also add on the specified
        format to the id_token
        Args:
            token_format (str): Format for the id_token:  valid values
            (standard or full)
        Returns:
            google.auth.service_account.IDTokenCredentials: A new credentials
                instance.
        """
        return self.__class__(
            self._signer,
            service_account_email=self._service_account_email,
            token_uri=self._token_uri,
            target_audience=self._target_audience,
            additional_claims=self._additional_claims.copy(),
            token_format=token_format,
            include_license=self._include_license)

    def with_license(self, include_license=False):
        """Create a copy of these credentials but also add on license
        informaton to the id_token
        Args:
            include_license (bool): Add license information to the id_token
        Returns:
            google.auth.service_account.IDTokenCredentials: A new credentials
                instance.
        """
        self._token_format = 'full'
        return self.__class__(
            self._signer,
            service_account_email=self._service_account_email,
            token_uri=self._token_uri,
            target_audience=self._target_audience,
            additional_claims=self._additional_claims.copy(),
            token_format=self._token_format,
            include_license=include_license)
