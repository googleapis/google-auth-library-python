# Copyright 2022 Google LLC
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

"""Headful Credentials.
Headful Credentials are …

Example headful credential:
{
  "type": "external_account_authorized_user",
  "audience": "//iam.googleapis.com/locations/global/workforcePools/$WORKFORCE_POOL_ID/providers/$PROVIDER_ID",
  "refresh_token": "refreshToken",
  "token_url": "https://sts.googleapis.com/v1/oauth/token",
  "token_info_url": "https://sts.googleapis.com/v1/instrospect"
  "client_id": "clientId",
  "client_secret": "clientSecret"
}
"""

_HEADFUL_JSON_TYPE = "external_account_authorized_user"

class Credentials(external_account.Credentials):
    """
    """

    def __init__(
        self,
        audience,
        refresh_token,
        token_url,
        token_info_url,
        client_id,
        client_secret,
        revoke_url="",
        quota_project_id="",
    ):
        """Instantiates a headful credentials object."""
        super(Credentials, self).__init__(
            audience=audience,
            subject_token_type=None,
            token_url=token_url,
            token_info_url=token_info_url,
            revoke_url=revoke_url,
            credential_source=None,
            client_id=client_id,
            client_secret=client_secret,
            quota_project_id=quota_project_id,
        )

        self._refresh_token = refresh_token
        self._token_info_url = token_info_url

    @property
    def info(self):
        """Generates the dictionary representation of the current credentials.

        Returns:
            Mapping: The dictionary representation of the credentials. This is the
                reverse of "from_info" defined on the subclasses of this class. It is
                useful for serializing the current credentials so it can deserialized
                later.
        """
        config_info = {
            "type": _HEADFUL_JSON_TYPE,
            "audience": self._audience,
            "refresh_token": self._refresh_token,
            "token_url": self._token_url,
            "token_info_url": self._token_info_url,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        return {key: value for key, value in config_info.items() if value is not None}

    @property
    def constructor_args(self):
        return {
            "audience": audience,
            "refresh_token": refresh_token,
            "token_url": token_url,
            "token_info_url": token_info_url,
            "client_id": client_id,
            "client_secret": client_secret,
            "revoke_url": revoke_url,
            "quota_project_id": quota_project_id
        )

    @property
    def requires_scopes(self):
        """Checks if the credentials requires scopes.

        Returns:
            bool: True if there are no scopes set otherwise False.
        """
        return False

    def _make_sts_request(self, request):
        return self._sts_client.refresh_token(request, self._refresh_token)

    def with_scopes(self, scopes, default_scopes=None):
        raise NotImplementedError("with_scopes is not available for this class")

    @classmethod
    def from_info(cls, info, **kwargs):
        """Creates a Credentials instance from parsed external account info.

        Args:
            info (Mapping[str, str]): The external account info in Google
                format.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            google.auth.identity_pool.Credentials: The constructed
                credentials.

        Raises:
            ValueError: For invalid parameters.
        """
        return cls(
            audience=info.get("audience"),
            refresh_token=info.get("refresh_token"),
            token_url=info.get("token_url"),
            token_info_url=info.get("token_info_url"),
            client_id=info.get("client_id"),
            client_secret=info.get("client_secret"),
            **kwargs
        )
