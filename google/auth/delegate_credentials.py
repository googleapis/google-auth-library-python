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
Credential object as the "Service Account Token Creator" role on the target
service account.

    .. _IAM Credentials API:
        https://cloud.google.com/iam/credentials/reference/rest/
"""

import copy
import datetime
import json

from google.auth import _helpers
from google.auth import credentials
from google.auth import exceptions

from google.auth.transport.requests import AuthorizedSession, Request

_DEFAULT_TOKEN_LIFETIME_SECS = 3600  # 1 hour in seconds

_IAM_SCOPE = ['https://www.googleapis.com/auth/iam']

# Number of seconds before token expiration to initiate a refresh
_CLOCK_SKEW_SECS = 30
_CLOCK_SKEW = datetime.timedelta(seconds=_CLOCK_SKEW_SECS)

_IAM_CREDENTIALS_ENDPOINT = 'https://iamcredentials.googleapis.com/v1/projects/'


class DelegateCredentials(credentials.Credentials):
    """This module defines delegate credentials which are essentially
    impersonated identities.

    When the `Service Account Token Creator_` IAM role is granted to a
    service account, any other identity that has that capability can
    impersonate that service account.
    For more information about Token Creator IAM role and
    IAMCredentials API, see `IAM documentation`.

    .. _Service Account Token Creator:
        https://cloud.google.com/iam/docs/service-accounts#the_service_account_token_creator_role

    Usage:
    First grant root_credentials the `Service Account Token Creator`
    role on the account to impersonate.   In this example, the
    service account represented by svc_account.json has the
    token creator role on
    `impersonated-account@_project_.iam.gserviceaccount.com`.

    Second, enable `iamcredentials.googleapis.com` API on the project
    represented by `svc_account.json`


    First initialze a root credential which does not have access to list bucket::

        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = '/path/to/svc_account.json'
        scopes = ['https://www.googleapis.com/auth/devstorage.read_only']
        
        root_credentials, project = google.auth.default(scopes=scopes)
        client = storage.Client(credentials=root_credentials)
        buckets = client.list_buckets(project='your_project')
        for bkt in buckets:
          print bkt


    Now use the root credentials to acquire credentials to impersonate another user::

        new_scopes = scopes
        delegate_credentials = DelegateCredentials(
          root_credentials = root_credentials,
          principal='impersonated-account@_project_.iam.gserviceaccount.com',
          new_scopes = new_scopes,
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
                 lifetime=_DEFAULT_TOKEN_LIFETIME_SECS):
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
                be valid for (max 3600).
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
        self._root_credentials.refresh(request)
        self._updateToken()

    @property
    def expired(self):
        skewed_expiry = self.expiry - _CLOCK_SKEW
        return _helpers.utcnow() >= skewed_expiry

    def _updateToken(self):
        """Updates the delegate credentials with a new access_token representing
        the delegated account.

        Raises:
            DefaultCredentialsError: Raised if the delegated credentials
            are not available.  Common reasons are
            `iamcredentials.googleapis.com` is not enabled or the
            `Service Account Token Creator` is not assigned
        """
        req = Request()
        self._root_credentials.refresh(req)

        body = {
            "delegates": self._delegates,
            "scope": self._new_scopes,
            "lifetime": str(self._lifetime) + "s"
        }
        iam_endpoint = ('{}-/serviceAccounts/{}:generateAccessToken').format(_IAM_CREDENTIALS_ENDPOINT, self._principal)
        try:
            authed_session = AuthorizedSession(self._root_credentials)
            response = authed_session.post(iam_endpoint,
                                           headers={'Content-Type': 'application/json'},
                                           json=body)
            if (response.status_code == 200):
                token_response = json.loads(response.content)
                self.token = token_response['accessToken']
                self.expiry = datetime.datetime.strptime(token_response['expireTime'], '%Y-%m-%dT%H:%M:%SZ')
            else:
                raise exceptions.DefaultCredentialsError("Unable to acquire delegated credentials " +
                                                         self._principal)
        except (exceptions.TransportError, ValueError, KeyError):
            raise exceptions.DefaultCredentialsError("Unable to acquire delegated credentials " +
                                                     self._principal)
