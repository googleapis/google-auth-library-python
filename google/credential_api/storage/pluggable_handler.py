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

import subprocess

from google.credential_api.storage.storage_handler import StorageHandler

class PluggableHandler(StorageHandler):
    def __init__(self, config_json):
        super().__init__(config_json)
        self.read_command = config_json["read"]
        self.write_command = config_json["write"]
        self.delete_command = config_json["delete"]
        self.list_command = config_json["list"]

    def write(self, credential_uri, credential_json):
        cmd = str.format(self.write_command, cred_id= credential_uri, cred_json=credential_json)
        return self.run_command(cmd)

    def delete(self, credential_uri):
        cmd = str.format(self.delete_command, cred_id=credential_uri)
        return self.run_command(cmd)
    
    def list(self):
        return self.run_command(self.list_command)

    def read(self, credential_uri):
        cmd = str.format(self.read_command, cred_id=credential_uri)
        return self.run_command(cmd)
    
    def run_command(self, cmd):
        result = subprocess.run(cmd, shell=True, capture_output=True)
        result = result.stdout.decode('utf-8')
        return result