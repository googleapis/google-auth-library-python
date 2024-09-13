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

import os
import io
import pickle

from google.credential_api.storage.storage_handler import StorageHandler

class FileStorageHandler(StorageHandler):
    def __init__(self, config_json):
        super().__init__(config_json)
        self.store_path = config_json["store_path"]
        self._load()       

    def write(self, credential_uri, credential_json):
        self.credentials[credential_uri] = credential_json
        self._save()
        return True

    def delete(self, credential_uri):
        self._load()
        self.credentials.pop(credential_uri, None)
        self._save()

    def list(self):
        self._load()
        keys = tuple(self.credentials.keys())
        return keys

    def read(self, credential_uri):
        self._load()
        return self.credentials.get(credential_uri)
    
    def _load(self):
        if bool(self.credentials):
            return

        if not os.path.exists(self.store_path):
            self.credentials= {}
        else:
            with io.open(self.store_path, "rb") as file_obj:
                self.credentials = pickle.load(file_obj)
    
    def _save(self):
        try:
            with io.open(self.store_path, "wb") as file_obj:
                pickle.dump(self.credentials, file_obj)
        except Exception as e:
            print(e)