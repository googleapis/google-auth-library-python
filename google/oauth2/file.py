# Copyright 2019 Google Inc. All rights reserved.
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

"""Utilities for OAuth.
Utilities for making it easier to work with OAuth 2.0
credentials.

Adjusted from https://github.com/googleapis/oauth2client
"""

import os
import threading
import io
import pathlib

from google.auth import _helpers
from google.auth import storage


class Storage(storage.Storage):
    """Store and retrieve a single credential to and from a file."""

    def __init__(self, filename):
        super().__init__(lock=threading.Lock())
        self._filename = filename
        self._pp = pathlib.Path(filename)

    def locked_get(self):
        """Retrieve Credential from file.
        Returns:
            google.auth.credentials.Credentials
        Raises:
            IOError if the file is a symbolic link.
        """
        credentials = None
        _helpers.validate_file(self._filename)
        try:
            f = io.open(self._filename, 'rb')
            content = f.read()
            f.close()
        except IOError:
            return credentials

        try:
            credentials = client.Credentials.new_from_json(content)
            credentials.set_store(self)
        except ValueError:
            pass

        return credentials

    def _create_file_if_needed(self):
        """Create an empty file if necessary.
        This method will not initialize the file. Instead it implements a
        simple version of "touch" to ensure the file has been created.
        """
        if not self._pp.exists():
            old_umask = os.umask(0o177)
            try:
                io.open(self._filename, 'a+b').close()
            finally:
                os.umask(old_umask)

    def locked_put(self, credentials):
        """Write Credentials to file.
        Args:
            credentials: Credentials, the credentials to store.
        Raises:
            IOError if the file is a symbolic link.
        """
        self._create_file_if_needed()
        _helpers.validate_file(self._filename)
        f = io.open(self._filename, 'w')
        f.write(credentials.to_json())
        f.close()

    def locked_delete(self):
        """Delete Credentials file.
        Args:
            credentials: Credentials, the credentials to store.
        """
        self._pp.unlink()
