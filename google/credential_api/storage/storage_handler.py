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

import abc

class StorageHandler(metaclass=abc.ABCMeta):
    def __init__(self, config_json) -> None:
        self.config_json = config_json

    def get_config(self):
        return self.config_json

    @abc.abstractmethod
    def write(self, credential_uri, credential_json):
        raise NotImplementedError()

    @abc.abstractmethod
    def delete(self, credential_uri):
        raise NotImplementedError()
    
    @abc.abstractmethod
    def list(self):
        raise NotImplementedError()
    
    def delete_all(self):
        creds = self.list()
        for credential_uri in creds:
            self.delete(credential_uri)

    @abc.abstractmethod
    def read(self, credential_uri):
        raise NotImplementedError()