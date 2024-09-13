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

from google.credential_api.mappings_file_system import MappingsFileSystem

class CredentialAPI:
    def __init__(self):
        self.credential_mapping = MappingsFileSystem("credential_mapping.txt")
        self.storage_mapping = MappingsFileSystem("storage_mapping.txt")

    def store_credential(self, credential_id, storage_id, credential_json):
        storage_handler =self.storage_mapping.read(storage_id)
        storage_handler.write(credential_id, credential_json)
        self.credential_mapping.write(credential_id, storage_id)

        return "True"

    def retrieve_credential(self, credential_id):
        if credential_id == 'default':
            credential_id = self.credential_mapping.read('default')

        storage_id = self.credential_mapping.read(credential_id)
        storage_handler = self.storage_mapping.read(storage_id)
        return storage_handler.read(credential_id)
    
    def delete_credential(self, credential_id):
        storage_id = self.credential_mapping.read(credential_id)
        storage_handler = self.storage_mapping.read(storage_id)
        storage_handler.delete(credential_id)
        self.credential_mapping.delete(credential_id)
        return "True"
    
    def list_credentials(self):
        return self.credential_mapping.list()
    
    def set_default_credential(self, credential_id):
        self.credential_mapping.write('default', credential_id)
        return "True"
