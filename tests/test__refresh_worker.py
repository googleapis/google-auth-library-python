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

import queue
import threading
import time

import mock
import pytest  # type: ignore

from google.auth import _refresh_worker, credentials, exceptions

MAIN_THREAD_SLEEP_MS = 100 / 1000


class MockCredentialsImpl(credentials.Credentials):
    def __init__(self, sleep_seconds=None):
        self.refresh_count = 0
        self.token = None
        self.sleep_seconds = sleep_seconds if sleep_seconds else None

    def refresh(self, request):
        if self.sleep_seconds:
            time.sleep(self.sleep_seconds)
        self.token = request
        self.refresh_count += 1


@pytest.fixture
def test_thread_count():
    return 25


def _cred_spinlock(cred):
    while cred.token is None:
        time.sleep(MAIN_THREAD_SLEEP_MS)


def test_invalid_start_refresh():
    w = _refresh_worker.RefreshWorker()
    with pytest.raises(exceptions.InvalidValue):
        w.start_refresh(None, None)


def test_queue_size():
    w = _refresh_worker.RefreshWorker()

    assert (
        w._refresh_queue.maxsize == _refresh_worker.RefreshWorker.MAX_REFRESH_QUEUE_SIZE
    )


def test_start_refresh():
    w = _refresh_worker.RefreshWorker()
    cred = MockCredentialsImpl()
    request = mock.MagicMock()
    w.start_refresh(cred, request)

    assert w._worker is not None

    _cred_spinlock(cred)

    assert cred.token == request
    assert cred.refresh_count == 1


def test_start_refresh_full_queue():
    w = _refresh_worker.RefreshWorker()
    cred = MockCredentialsImpl()
    request = mock.MagicMock()
    with mock.patch(
        "queue.Queue.put_nowait",
        side_effect=queue.Full("Queue was full when put was called"),
    ):
        w.start_refresh(cred, request)
    assert not cred.token


def test_start_refresh_starve_queue():
    w = _refresh_worker.RefreshWorker()

    with mock.patch(
        "queue.Queue.get",
        side_effect=queue.Empty("Queue was empty when get was called"),
    ):
        w._spawn_worker()
        # wait for worker to timeout waiting for work.
        while w._worker.is_alive():
            time.sleep(5 / 1000)  # pragma: NO COVER

    assert not w._worker.is_alive()


def test_nonblocking_start_refresh():
    w = _refresh_worker.RefreshWorker()
    cred = MockCredentialsImpl(sleep_seconds=1)
    request = mock.MagicMock()
    w.start_refresh(cred, request)

    assert w._worker is not None
    assert not cred.token
    assert cred.refresh_count == 0


def test_multiple_refreshes_one_worker(test_thread_count):
    cred_sleep_ms = MAIN_THREAD_SLEEP_MS + (500 / 1000)

    w = _refresh_worker.RefreshWorker()
    cred = MockCredentialsImpl(sleep_seconds=cred_sleep_ms)
    request = mock.MagicMock()

    def _thread_refresh():
        w.start_refresh(cred, request)
        time.sleep(MAIN_THREAD_SLEEP_MS)

    threads = [
        threading.Thread(target=_thread_refresh) for _ in range(test_thread_count)
    ]
    for t in threads:
        t.start()

    # All the spawn threads should exit before the refresh worker finishes the
    # refresh.
    _cred_spinlock(cred)

    assert cred.token == request
    assert cred.refresh_count == 1


def test_multiple_refreshes_multiple_workers(test_thread_count):
    w = _refresh_worker.RefreshWorker()
    cred = MockCredentialsImpl()
    request = mock.MagicMock()

    def _thread_refresh():
        w.start_refresh(cred, request)

    threads = [
        threading.Thread(target=_thread_refresh) for _ in range(test_thread_count)
    ]
    for t in threads:
        t.start()

    _cred_spinlock(cred)

    assert cred.token == request
    # There is a chance only one thread has enough time to perform a refresh.
    # Generally multiple threads will have time to perform a refresh
    assert cred.refresh_count > 0
