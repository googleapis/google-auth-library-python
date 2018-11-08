# Copyright 2018 Google Inc.
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

"""Google Cloud Impersonated credentials.

This module provides authentication for applications where local credentials
impersonates a remote service account using `IAM Credentials API`_.

This class can be used to impersonate a service account as long as the original
Credential object has the "Service Account Token Creator" role on the target
service account.

    .. _IAM Credentials API:
        https://cloud.google.com/iam/credentials/reference/rest/
"""

import copy
from datetime import datetime
import json

from google.auth import _helpers
from google.auth import credentials
from google.auth import exceptions

_DEFAULT_TOKEN_LIFETIME_SECS = 3600  # 1 hour in seconds

_IAM_SCOPE = ['https://www.googleapis.com/auth/iam']

_IAM_ENDPOINT = ('https://iamcredentials.googleapis.com/v1/projects/-' +
                 '/serviceAccounts/{}:generateAccessToken')

_REFRESH_ERROR = 'Unable to acquire impersonated credentials '
_LIFETIME_ERROR = 'Credentials with lifetime set cannot be renewed'


class ImpersonatedCredentials(credentials.Credentials):
    """This module defines impersonated credentials which are essentially
    impersonated identities.

    Impersonated Credentials allows credentials issued to a user or
    service account to impersonate another. The target service account must
    grant the orginating credential principal the
    `Service Account Token Creator`_ IAM role:

    For more information about Token Creator IAM role and
    IAMCredentials API, see
    `Creating Short-Lived Service Account Credentials`_.

    .. _Service Account Token Creator:
        https://cloud.google.com/iam/docs/service-accounts#the_service_account_token_creator_role

    .. _Creating Short-Lived Service Account Credentials:
        https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials

    Usage:

    First grant source_credentials the `Service Account Token Creator`
    role on the target account to impersonate.   In this example, the
    service account represented by svc_account.json has the
    token creator role on
    `impersonated-account@_project_.iam.gserviceaccount.com`.

    Initialze a source credential which does not have access to
    list bucket::

        target_scopes = ['https://www.googleapis.com/auth/devstorage.read_only']
        source_credentials = service_account.Credentials.from_service_account_file(
            '/path/to/svc_account.json',
            scopes=target_scopes)

    Now use the source credentials to acquire credentials to impersonate
    another service account::

        target_credentials = ImpersonatedCredentials(
          source_credentials = source_credentials,
          target_principal='impersonated-account@_project_.iam.gserviceaccount.com',
          target_scopes = target_scopes,
          delegates=[],
          lifetime=500)

    Resource access is granted::

        client = storage.Client(credentials=target_credentials)
        buckets = client.list_buckets(project='your_project')
        for bucket in buckets:
          print bucket.name
    """

    def __init__(self, source_credentials,  target_principal,
                 target_scopes, delegates=None,
                 lifetime=None):
        """
        Args:
            source_credentials (google.auth.Credentials): The source credential
                used as to acquire the impersonated credentials.
            target_principal (str): The service account to impersonate.
            target_scopes (Sequence[str]): Scopes to request during the
                authorization grant.
            delegates (Sequence[str]): The chained list of delegates required
                to grant the final access_token.  If set, the sequence of
                identities must have "Service Account Token Creator" capability
                granted to the prceeding identity.  For example, if set to
                [serviceAccountB, serviceAccountC], the source_credential
                must have the Token Creator role on serviceAccountB.
                serviceAccountB must have the Token Creator on serviceAccountC.
                Finally, C must have Token Creator on target_principal.
                If left unset, source_credential must have that role on
                target_principal.
            lifetime (int): Number of seconds the delegated credential should
                be valid for (upto 3600).  If set, the credentials will
                **not** get refreshed after expiration.  If not set, the
                credentials will be refreshed every 3600s.
        """

        super(credentials.Credentials, self).__init__()

        self._source_credentials = copy.copy(source_credentials)
        self._source_credentials._scopes = _IAM_SCOPE
        self._target_principal = target_principal
        self._target_scopes = target_scopes
        self._delegates = delegates
        self._lifetime = lifetime
        self.token = None
        self.expiry = _helpers.utcnow()

    @_helpers.copy_docstring(credentials.Credentials)
    def refresh(self, request):
        if (self.token is not None and self._lifetime is not None):
            self.expiry = _helpers.utcnow()
            raise exceptions.RefreshError(_LIFETIME_ERROR)
        self._source_credentials.refresh(request)
        self._update_token(request)

    @property
    def expired(self):
        return _helpers.utcnow() >= self.expiry

    def _make_iam_token_request(self, request, headers, body):
        """
        Args:
            headers (Mapping[str, str]): Map of headers to transmit.
            body (Mapping[str, str]): JSON Payload body for the iamcredentials
                API call.                     
        Raises:
            TransportError: Raised if there is an underlying HTTP connection
            Error
            DefaultCredentialsError: Raised if the impersonated credentials
            are not available.  Common reasons are
            `iamcredentials.googleapis.com` is not enabled or the
            `Service Account Token Creator` is not assigned        
        """
        iam_endpoint = _IAM_ENDPOINT.format(self._target_principal)
        try:
            response = request(url=iam_endpoint,
                           method='POST',
                           headers=headers,
                           json=body)
            if (response.status == 200):
                token_response = json.loads(response.data.decode('utf-8'))
                self.token = token_response['accessToken']
                self.expiry = datetime.strptime(token_response['expireTime'],
                                                '%Y-%m-%dT%H:%M:%SZ')
            else:
                raise exceptions.DefaultCredentialsError(_REFRESH_ERROR +
                                                         self._target_principal)
        except (ValueError, KeyError, TypeError):
            raise exceptions.DefaultCredentialsError(_REFRESH_ERROR +
                                                     self._target_principal)
        except (exceptions.TransportError):
            raise exceptions.TransportError(_REFRESH_ERROR +
                                            self._target_principal)

    def _update_token(self, request):
        """Updates credentials with a new access_token representing
        the impersonated account.

        Args:
            request (google.auth.transport.requests.Request): Request object to use
                for refreshing credentials.
        """

        lifetime = self._lifetime
        if (self._lifetime is None):
            lifetime = _DEFAULT_TOKEN_LIFETIME_SECS
        body = {
            "delegates": self._delegates,
            "scope": self._target_scopes,
            "lifetime": str(lifetime) + "s"
        }

        headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + self._source_credentials.token
        }
        self._make_iam_token_request(request=request,
            headers=headers, body=body)
