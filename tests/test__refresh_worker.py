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

import random
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
    while cred.token is None:  # pragma: NO COVER
        time.sleep(MAIN_THREAD_SLEEP_MS)


def test_invalid_start_refresh():
    w = _refresh_worker.RefreshThreadManager()
    with pytest.raises(exceptions.InvalidValue):
        w.start_refresh(None, None)


def test_queue_size():
    w = _refresh_worker.RefreshThreadManager()

    assert (
        w._error_queue.maxsize
        == _refresh_worker.RefreshThreadManager.MAX_ERROR_QUEUE_SIZE
    )


def test_start_refresh():
    w = _refresh_worker.RefreshThreadManager()
    cred = MockCredentialsImpl()
    request = mock.MagicMock()
    w.start_refresh(cred, request)

    assert w._worker is not None

    _cred_spinlock(cred)

    assert cred.token == request
    assert cred.refresh_count == 1


def test_nonblocking_start_refresh():
    w = _refresh_worker.RefreshThreadManager()
    cred = MockCredentialsImpl(sleep_seconds=1)
    request = mock.MagicMock()
    w.start_refresh(cred, request)

    assert w._worker is not None
    assert not cred.token
    assert cred.refresh_count == 0


def test_multiple_refreshes_multiple_workers(test_thread_count):
    w = _refresh_worker.RefreshThreadManager()
    cred = MockCredentialsImpl()
    request = mock.MagicMock()

    def _thread_refresh():
        time.sleep(random.randrange(0, 5))
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


def test_refresh_error():
    w = _refresh_worker.RefreshThreadManager()
    cred = mock.MagicMock()
    request = mock.MagicMock()

    cred.refresh.side_effect = exceptions.RefreshError("Failed to refresh")

    w.start_refresh(cred, request)

    err = None
    while err is None:
        err = w.get_error()
        time.sleep(MAIN_THREAD_SLEEP_MS)

    assert isinstance(err, exceptions.RefreshError)

    with pytest.raises(exceptions.RefreshError):
        for _ in range(0, w.MAX_ERROR_QUEUE_SIZE + 1):
            w.start_refresh(cred, request)

    while w._error_queue.empty():  # pragma: NO COVER
        time.sleep(MAIN_THREAD_SLEEP_MS)
    assert not w._error_queue.empty()

    w.flush_error_queue()
    assert w._error_queue.empty()

    # Make sure that an empty queue doesn't result in exceptions.
    w.flush_error_queue()
    assert w._error_queue.empty()


def test_refresh_dead_worker():
    cred = MockCredentialsImpl()
    request = mock.MagicMock()

    w = _refresh_worker.RefreshThreadManager()
    w._worker = None

    w.start_refresh(cred, request)

    _cred_spinlock(cred)

    assert cred.token == request
    assert cred.refresh_count == 1


def test_empty_error_queue():
    w = _refresh_worker.RefreshThreadManager()
    assert not w.error_queue_full()


def test_full_error_queue():
    w = _refresh_worker.RefreshThreadManager()
    w._error_queue = mock.MagicMock()
    w._error_queue.returns = True
    assert w.error_queue_full()
