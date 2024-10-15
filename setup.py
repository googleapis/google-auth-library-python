# Copyright 2014 Google Inc.
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

import os

from setuptools import find_namespace_packages
from setuptools import setup


package_root = os.path.abspath(os.path.dirname(__file__))

setup(
    url="https://github.com/googleapis/google-auth-library-python",
    packages=find_namespace_packages(
        exclude=("tests*", "system_tests*", "docs*", "samples*")
    ),
    package_data={"google.auth": ["py.typed"], "google.oauth2": ["py.typed"]},
)
