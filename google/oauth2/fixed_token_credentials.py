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

"""Credentials with a fixed OAuth2 token.

This module provides credentials with a fixed OAuth2 token. The token is
considered never expired so users are responsible for the validity of
the token.
"""

from google.auth import _helpers
from google.auth import credentials


class FixedTokenCredentials(credentials.Credentials):
    """Credentials with a fixed OAuth2 token.
    
    The token is considered never expired so users are responsible for the
    validity of the token.
    """

    def __init__(self, token):
        """
        Args:
            token (str): OAuth2 token string
        Raises:
            ValueError: If the token is not provided
        """
        if not token:
            raise ValueError("Token is not provided")
        super(FixedTokenCredentials, self).__init__()
        self.token = token

    @property
    def expired(self):
        return False

    @property
    def valid(self):
        return True

    @_helpers.copy_docstring(credentials.Credentials)
    def refresh(self, request):
        return