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
import queue
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
        """Initializes the worker."""

        self._worker = None
        self._lock = threading.Lock()
        self._error_queue = queue.Queue(self.MAX_ERROR_QUEUE_SIZE)

    def _need_worker(self):
        return self._worker is None or not self._worker.is_alive()

    def _spawn_worker(self, cred, request):
        self._worker = RefreshThread(
            cred=cred, request=request, error_queue=self._error_queue
        )
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

        if self._error_queue.full():
            raise e.RefreshError(
                "Could not start a background refresh. The error queue is full. After addressing the errors in the error queue, drain the queue with `credential.flush_error_queue()`."
            )

        with self._lock:
            if self._need_worker():  # pragma: NO COVER
                self._spawn_worker(cred, request)

    def error_queue_full(self):
        """
      True if the refresh worker error queue is full. False if it is not yet full.

      Returns:
        bool
      """
        return self._error_queue.full()

    def flush_error_queue(self):
        """
      Drop all errors in the error queue.
      """
        try:
            while not self._error_queue.empty():
                _ = self._error_queue.get_nowait()
        except queue.Empty:  # pragma: NO COVER
            pass

    def get_error(self):
        """
        Returns the first error in the error queue. It is recommended to flush the full error queue to root cause refresh failures.
        Returns:
          Optional[exceptions.Exception]
        """
        try:
            return self._error_queue.get_nowait()
        except queue.Empty:
            return None


class RefreshThread(threading.Thread):
    """
    Thread that refreshes credentials.
    """

    def __init__(self, cred, request, error_queue, **kwargs):
        """Initializes the thread.

        Args:
            cred: A Credential object to refresh.
            request: A Request object used to perform a credential refresh.
            error_queue: A queue containing errors that prevented a credential refresh.
            **kwargs: Additional keyword arguments.
        """

        super().__init__(**kwargs)
        self._cred = cred
        self._request = request
        self._error_queue = error_queue

    def run(self):
        """
        """
        try:
            self._cred.refresh(self._request)
        except Exception as err:  # pragma: NO COVER
            _LOGGER.error(f"Background refresh failed due to: {err}")
            if not self._error_queue.full():
                self._error_queue.put_nowait(err)
