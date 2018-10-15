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

"""Google Cloud Delegated credentials.

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

_REFRESH_ERROR = 'Unable to acquire delegated credentials '
_LIFETIME_ERROR = 'Delegate Credentials with lifetime set cannot be renewed'


class DelegateCredentials(credentials.Credentials):
    """This module defines delegate credentials which are essentially
    impersonated identities.

    Delegate Credentials allows credentials issued to a user or
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

    First grant root_credentials the `Service Account Token Creator`
    role on the account to impersonate.   In this example, the
    service account represented by svc_account.json has the
    token creator role on
    `impersonated-account@_project_.iam.gserviceaccount.com`.

    Initialze a root credential which does not have access to
    list bucket::

        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'svc_account.json'
        scopes = ['https://www.googleapis.com/auth/devstorage.read_only']

        root_credentials, project = google.auth.default(scopes=scopes)

    Now use the root credentials to acquire credentials to impersonate
    another service account::

        delegate_credentials = DelegateCredentials(
          root_credentials = root_credentials,
          principal='impersonated-account@_project_.iam.gserviceaccount.com',
          new_scopes = scopes,
          delegates=[],
          lifetime=500)

    Resource access is granted::

        client = storage.Client(credentials=delegate_credentials)
        buckets = client.list_buckets(project='your_project')
        for bkt in buckets:
          print bkt.name
    """

    def __init__(self, root_credentials,  principal,
                 new_scopes, delegates=None,
                 lifetime=None):
        """
        Args:
            root_credentials (google.auth.Credentials): The root credential
                used as to acquire the delegated credentials.
            principal (str): The service account to impersonatge.
            new_scopes (Sequence[str]): Scopes to request during the
                authorization grant.
            delegates (Sequence[str]): The chained list of delegates required
                to grant the final access_token.
            lifetime (int): Number of seconds the delegated credential should
                be valid for (upto 3600).  If set, the credentials will
                **not** get refreshed after expiration.  If not set, the
                credentials will be refreshed every 3600s.
        """

        super(credentials.Credentials, self).__init__()

        self._root_credentials = copy.copy(root_credentials)
        self._root_credentials._scopes = _IAM_SCOPE
        self._principal = principal
        self._new_scopes = new_scopes
        self._delegates = delegates
        self._lifetime = lifetime
        self.token = None
        self.expiry = _helpers.utcnow()

    @_helpers.copy_docstring(credentials.Credentials)
    def refresh(self, request):
        if (self.token is not None and self._lifetime is not None):
            self.expiry = _helpers.utcnow()
            raise exceptions.RefreshError(_LIFETIME_ERROR)
        self._root_credentials.refresh(request)
        self._updateToken(request)

    @property
    def expired(self):
        return _helpers.utcnow() >= self.expiry

    def _updateToken(self, req):
        """Updates the delegate credentials with a new access_token representing
        the delegated account.

        Args:
            req (google.auth.transport.requests.Request): Request object to use
                for refreshing credentials.

        Raises:
            TransportError: Raised if there is an underlying HTTP connection
            Error
            DefaultCredentialsError: Raised if the delegated credentials
            are not available.  Common reasons are
            `iamcredentials.googleapis.com` is not enabled or the
            `Service Account Token Creator` is not assigned
        """

        lifetime = self._lifetime
        if (self._lifetime is None):
            lifetime = _DEFAULT_TOKEN_LIFETIME_SECS
        body = {
            "delegates": self._delegates,
            "scope": self._new_scopes,
            "lifetime": str(lifetime) + "s"
        }

        iam_endpoint = _IAM_ENDPOINT.format(self._principal)
        try:
            headers = {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + self._root_credentials.token
            }
            response = req(url=iam_endpoint,
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
                                                         self._principal)
        except (ValueError, KeyError, TypeError):
            raise exceptions.DefaultCredentialsError(_REFRESH_ERROR +
                                                     self._principal)
        except (exceptions.TransportError):
            raise exceptions.TransportError(_REFRESH_ERROR +
                                            self._principal)
