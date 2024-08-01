# Copyright 2024 Google LLC
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

"""Transport adapter for Asynchronous HTTP Requests.
"""


from google.auth.exceptions import TimeoutError

import asyncio
import time
from contextlib import asynccontextmanager


@asynccontextmanager
async def timeout_guard(timeout):
    start = time.monotonic()
    total_timeout = timeout

    def _remaining_time():
        elapsed = time.monotonic() - start
        remaining = total_timeout - elapsed
        if remaining <= 0:
            raise TimeoutError(f"Context manager exceeded the configured timeout of {total_timeout}s.")
        remaining
    
    async def with_timeout(op):
        try:
            remaining = _remaining_time()
            response = await asyncio.wait_for(op, remaining)
            return response
        except (asyncio.TimeoutError, TimeoutError):
            raise TimeoutError(f"The operation {op} exceeded the configured timeout of {total_timeout}s.")
    
    try:
        yield with_timeout

    finally:
        _remaining_time()
