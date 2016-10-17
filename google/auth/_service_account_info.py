# Copyright 2016 Google Inc.
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

"""Helper functions for loading data from a Google service account file."""

import io
import json

from google.auth import crypt


def from_dict(data, require=None):
    """Validates a dictionary containing Google service account data and
    creates a :class:`google.auth.crypt.Signer` instance.

    Args:
        data (Mapping[str, str]): The service account data
        require (Sequence[str]): List of keys required to be present in the
            info.

    Returns:
        Tuple[ Mapping[str, str], google.auth.crypt.Signer ]: The verified
            info and a signer instance.

    Raises:
        ValueError: if the data was in the wrong format, or if one of the
            required keys is missing.
    """
    # Private key is always required.
    require = set((require or []) + ['private_key'])
    missing = require.difference(set(data.keys()))

    if missing:
        raise ValueError(
            'Service account info was not in the expected format, missing '
            'fields {}.'.format(', '.join(missing)))

    # Create a signer.
    signer = crypt.Signer.from_string(
        data['private_key'], data.get('private_key_id'))

    return data, signer


def from_filename(filename, require=None):
    """Reads a Google service account JSON file and returns its parsed info.

    Args:
        filename (str): The path to the service account .json file.
        require (Sequence[str]): List of keys required to be present in the
            info.

    Returns:
        Tuple[ Mapping[str, str], google.auth.crypt.Signer ]: The verified
            info and a signer instance.
    """
    with io.open(filename, 'r', encoding='utf-8') as json_file:
        data = json.load(json_file)
        return from_dict(data, require=require)
