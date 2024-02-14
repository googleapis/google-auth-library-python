# Copyright 2015 Google Inc.
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

"""Application default credentials.

Implements application default credentials and project ID detection.
"""

import logging
import requests

from google.auth import credentials

_LOGGER = logging.getLogger(__name__)

def default(scopes=None, request=None, quota_project_id=None, default_scopes=None):
    print('called default')
    response = requests.get('http://127.0.0.1:5000/default-cred')
    print(f'default-cred-resp:{response.text}')
    cred = credentials.Credentials(response.text)
    return cred, "effective_project_id"
