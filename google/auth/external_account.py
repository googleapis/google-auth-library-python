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

"""External Account Credentials.

This module provides credentials that exchange workload identity pool external
credentials for Google access tokens. This facilitates calling Google APIs from
Kubernetes, Azure and AWS workloads securely, using native credentials retrieved
from the current environment without the need to copy, save and manage service
account keys.

Specifically, this is intended to use access tokens acquired using the GCP STS
token exchange endpoint following the `OAuth 2.0 Token Exchange`_ spec.

.. _OAuth 2.0 Token Exchange: https://tools.ietf.org/html/rfc8693
"""

import abc
import datetime

import six

from google.auth import _helpers
from google.auth import credentials
from google.oauth2 import sts
from google.oauth2 import utils

# The token exchange grant_type used for exchanging credentials.
_STS_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
# The token exchange requested_token_type. This is always an access_token.
_STS_REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


@six.add_metaclass(abc.ABCMeta)
class Credentials(credentials.Scoped, credentials.CredentialsWithQuotaProject):
    """Base class for all external account credentials.

    This is used to instantiate Credentials for exchanging external account
    credentials for Google access token and authorizing requests to Google APIs.
    The base class implements the common logic for exchanging external account
    credentials for Google access tokens.
    """

    def __init__(
        self,
        audience,
        subject_token_type,
        token_url,
        credential_source,
        client_id=None,
        client_secret=None,
        quota_project_id=None,
        scopes=None,
    ):
        """Instantiates an external account credentials object.

        Args:
            audience (str): The STS audience field.
            subject_token_type (str): The subject token type.
            token_url (str): The STS endpoint URL.
            credential_source (Mapping): The credential source dictionary.
            client_id (Optional[str]): The optional client ID.
            client_secret (Optional[str]): The optional client secret.
            quota_project_id (Optional[str]): The optional quota project ID.
            scopes (Optional[Sequence[str]]): Optional scopes to request during the
                authorization grant.
        """
        super(Credentials, self).__init__()
        self._audience = audience
        self._subject_token_type = subject_token_type
        self._token_url = token_url
        self._credential_source = credential_source
        self._client_id = client_id
        self._client_secret = client_secret
        self._quota_project_id = quota_project_id
        self._scopes = scopes

        if self._client_id:
            self._client_auth = utils.ClientAuthentication(
                utils.ClientAuthType.basic, self._client_id, self._client_secret
            )
        else:
            self._client_auth = None
        self._sts_client = sts.Client(self._token_url, self._client_auth)

    @property
    def requires_scopes(self):
        """Checks if the credentials requires scopes.

        Returns:
            bool: True if there are no scopes set otherwise False.
        """
        return True if not self._scopes else False

    @_helpers.copy_docstring(credentials.Scoped)
    def with_scopes(self, scopes):
        return self.__class__(
            audience=self._audience,
            subject_token_type=self._subject_token_type,
            token_url=self._token_url,
            credential_source=self._credential_source,
            client_id=self._client_id,
            client_secret=self._client_secret,
            quota_project_id=self._quota_project_id,
            scopes=scopes,
        )

    @abc.abstractmethod
    def retrieve_subject_token(self, request):
        """Retrieves the subject token using the credential_source object.

        Args:
            request (google.auth.transport.Request): A callable used to make
                HTTP requests.
        Returns:
            str: The retrieved subject token.
        """
        # pylint: disable=missing-raises-doc
        # (pylint doesn't recognize that this is abstract)
        raise NotImplementedError("retrieve_subject_token must be implemented")

    @_helpers.copy_docstring(credentials.Credentials)
    def refresh(self, request):
        now = _helpers.utcnow()
        response_data = self._sts_client.exchange_token(
            request=request,
            grant_type=_STS_GRANT_TYPE,
            subject_token=self.retrieve_subject_token(request),
            subject_token_type=self._subject_token_type,
            audience=self._audience,
            scopes=self._scopes,
            requested_token_type=_STS_REQUESTED_TOKEN_TYPE,
        )

        self.token = response_data.get("access_token")
        lifetime = datetime.timedelta(seconds=response_data.get("expires_in"))
        self.expiry = now + lifetime

    @_helpers.copy_docstring(credentials.CredentialsWithQuotaProject)
    def with_quota_project(self, quota_project_id):
        # Return copy of instance with the provided quota project ID.
        return self.__class__(
            audience=self._audience,
            subject_token_type=self._subject_token_type,
            token_url=self._token_url,
            credential_source=self._credential_source,
            client_id=self._client_id,
            client_secret=self._client_secret,
            quota_project_id=quota_project_id,
            scopes=self._scopes,
        )
