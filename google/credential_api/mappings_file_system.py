# Copyright 2016 Google LLC
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

import json
import io
import os
import pickle

from google.credential_api.mappings_handler import MappingsHandler

class MappingsFileSystem(MappingsHandler):
    def __init__(self, mapping_path):
        self.mapping_path = mapping_path

        if not os.path.exists(mapping_path):
            self.mappings= {}
        else:
            with io.open(mapping_path, "rb") as file_obj:
                try:
                    self.mappings = pickle.load(file_obj)
                    print(self.mappings)
                except Exception as e:
                    print(e)

    def write(self, key, value):
        self.mappings[key] = value
        self._save()
        return True

    def delete(self, key):
        self.mappings.pop(key, None)
        self._save()

    def read(self, key):
        return self.mappings.get(key)
    
    def list(self):
        """Converts the keys in a dictionary to JSON format.

        Args:
            mappings (dict): The dictionary to convert.

        Returns:
            dict: The converted dictionary.
        """

        keys = []
        for key in self.mappings.keys():
            keys.append(key)

        return keys
    
    def _save(self):
        with io.open(self.mapping_path, "wb") as file_obj:
            try:
                pickle.dump(self.mappings, file_obj)
            except Exception as e:
                print(e)
