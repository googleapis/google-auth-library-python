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

from google.credential_api.mappings_file_system import MappingsFileSystem
from google.credential_api.storage.file_storage_handler import FileStorageHandler
from google.credential_api.storage.pluggable_handler import PluggableHandler

class StorageAPI:
    def __init__(self):
        self.storage_mapping = MappingsFileSystem("storage_mapping.txt")

    def RegisterStorageConfig(self, name, config):
        # config_json = json.loads(config)
        config_type = config["type"]
        id = config_type + "/" + name

        if config_type == "filesystem":
            storage_handler = FileStorageHandler(config)
        elif config_type == "pluggable":
            storage_handler = PluggableHandler(config)
        else:
            raise Exception("Unknown storage type: " + config_type)        

        try:
            self.storage_mapping.write(id, storage_handler)
        except Exception as e:
            raise Exception("Failed to register storage: " + str(e))
        
        return id
    
    def RetrieveStorageConfig(self, id):
        return self.storage_mapping.read(id).get_config()
    
    def DeleteStorageConfig(self, id, delete_credentials=False):
        handler = self.storage_mapping.read(id)
        if delete_credentials:
            handler.delete_all()
        self.storage_mapping.delete(id)
        return 'Deleted'
    
    def ListStorageConfigs(self):
        return self.storage_mapping.list()
    
