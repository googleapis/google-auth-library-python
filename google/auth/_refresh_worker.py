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

    def __init__(self):
        """Initializes the worker."""

        self._refresh_queue = queue.Queue(self.MAX_REFRESH_QUEUE_SIZE)
        self._worker = None

    def _need_worker(self):
        return not self._worker or not self._worker.is_alive()

    def _spawn_worker(self):
        self._worker = RefreshThread(work_queue=self._refresh_queue)
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

        if self._refresh_queue.qsize() >= self.MAX_REFRESH_QUEUE_SIZE:
            if self._need_worker():
                self._spawn_worker()
            return

        try:
            self._refresh_queue.put_nowait((cred, request))
        except queue.Full:
            return

        if self._need_worker():
            self._spawn_worker()


class RefreshThread(threading.Thread):
    """
    Thread that refreshes credentials.
    """

    def __init__(self, work_queue, **kwargs):
        """Initializes the thread.

        Args:
            work_queue: A queue of credentials and request tuples.
            **kwargs: Additional keyword arguments.
        """

        super().__init__(**kwargs)
        self._work_queue = work_queue

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
        cred.refresh(request)
        self._work_queue.task_done()
