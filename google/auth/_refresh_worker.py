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


class RefreshWorker:
    """
    A worker that will perform a non-blocking refresh of credentials.
    """

    MAX_REFRESH_QUEUE_SIZE = 1
    MAX_ERROR_QUEUE_SIZE = 2

    def __init__(self):
        """Initializes the worker."""

        self._refresh_queue = queue.Queue(self.MAX_REFRESH_QUEUE_SIZE)
        # Bound the error queue to avoid infinitely growing the heap.
        self._error_queue = queue.Queue(self.MAX_ERROR_QUEUE_SIZE)
        self._worker = None

    def _need_worker(self):
        return self._worker is None or not self._worker.is_alive()

    def _spawn_worker(self):
        self._worker = RefreshThread(
            work_queue=self._refresh_queue, error_queue=self._error_queue
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

        # This test case is covered by the unit tests but sometimes the cover
        # check can flake due to the schdule.
        #
        # Specifially this test is covered by test_refresh_dead_worker
        if not self._refresh_queue.empty(): # pragma: NO COVER
            if self._need_worker():
                self._spawn_worker()
            return

        try:
            self._refresh_queue.put_nowait((cred, request))
        except queue.Full:
            return

        if self._need_worker():
            self._spawn_worker()

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
        # This condition is unlikely but there is a possibility that an
        # error gets queued between the empty and get calls
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

    def __init__(self, work_queue, error_queue, **kwargs):
        """Initializes the thread.

        Args:
            work_queue: A queue of credentials and request tuples.
            error_queue: A queue containing errors that prevented a credential refresh.
            **kwargs: Additional keyword arguments.
        """

        super().__init__(**kwargs)
        self._work_queue = work_queue
        self._error_queue = error_queue

    def run(self):
        """
        Gets credentials and request objects from a queue.

        The thread will block until a work item appears from the queue.

        Once the refresh has completed, the thread will mark the queue task
        as complete, and exit.
        """
        try:
            cred, request = self._work_queue.get(timeout=WORKER_TIMEOUT_SECONDS)
        except queue.Empty:
            _LOGGER.error(
                f"Timed out waiting for refresh work after {WORKER_TIMEOUT_SECONDS} seconds. This could mean there is a race condition, work starvation, or other logic error in the refresh code."
            )
            return
        try:
            cred.refresh(request)
        except Exception as err:
            _LOGGER.error(f"Background refresh failed due to: {err}")
            if not self._error_queue.full():
                self._error_queue.put_nowait(err)

        # The coverage tool is not able to capturre this line, but it is covered
        # by test_start_refresh in the unit tests.
        self._work_queue.task_done()
