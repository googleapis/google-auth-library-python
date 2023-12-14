# Copyright 2023 Google LLC
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

import logging
import threading

import google.auth.exceptions as e

WORKER_TIMEOUT_SECONDS = 5

_LOGGER = logging.getLogger(__name__)


class RefreshThreadManager:
    """
    Organizes exactly one background job that refresh a token.
    """

    MAX_ERROR_QUEUE_SIZE = 2

    def __init__(self):
        """Initializes the manager."""

        self._worker = None
        self._lock = threading.Lock()

    def _need_worker(self):
        return self._worker is None or not self._worker.is_alive()

    def _spawn_worker(self, cred, request):
        self._worker = RefreshThread(cred=cred, request=request)
        self._worker.start()

    def start_refresh(self, cred, request):
        """Starts a refresh thread for the given credentials.
        The credentials are refreshed using the request parameter.
        request and cred MUST not be None

        Args:
            cred: A credentials object.
            request: A request object.
        """
        if cred is None or request is None:
            raise e.InvalidValue(
                "Unable to start refresh. cred and request must be valid and instantiated objects."
            )

        with self._lock:
            if self._worker is not None and self._worker._error_info is not None:
                raise e.RefreshError(
                    f"Could not start a background refresh. The background refresh previously failed with {self._worker._error_info}."
                ) from self._worker._error_info

        with self._lock:
            if self._need_worker():  # pragma: NO COVER
                self._spawn_worker(cred, request)

    def get_error(self):
        """
        Returns the error that occurred in the refresh thread. Clears the error once called.

        Returns:
          Optional[exceptions.Exception]
        """
        if not self._worker:
            return None
        err, self._worker._error_info = self._worker._error_info, None
        return err


class RefreshThread(threading.Thread):
    """
    Thread that refreshes credentials.
    """

    def __init__(self, cred, request, **kwargs):
        """Initializes the thread.

        Args:
            cred: A Credential object to refresh.
            request: A Request object used to perform a credential refresh.
            **kwargs: Additional keyword arguments.
        """

        super().__init__(**kwargs)
        self._cred = cred
        self._request = request
        self._error_info = None

    def run(self):
        """
        Perform the credential refresh.
        """
        try:
            self._cred.refresh(self._request)
        except Exception as err:  # pragma: NO COVER
            _LOGGER.error(f"Background refresh failed due to: {err}")
            self._error_info = err
