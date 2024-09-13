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

from google.credential_api.credential_api import CredentialAPI
from google.credential_api.storage.storage_api import StorageAPI

from flask import Flask, request

app = Flask(__name__)
credential_api = CredentialAPI()
storage_api = StorageAPI()

@app.route('/store_credential', methods=['POST'])
def store_credential():
    json = request.get_json()
    credential_id = json['credential_id']
    storage_id = json['storage_id']
    credential_json = json['credential_json']

    return credential_api.store_credential(credential_id, storage_id, credential_json)

@app.route('/retrieve_credential', methods=['GET'])
def retrieve_credential():
    credential_id = request.args.get('credential_id')

    credential = credential_api.retrieve_credential(credential_id)

    return credential

@app.route('/list_credentials', methods=['GET'])
def list_credentials():
    return credential_api.list_credentials()

@app.route('/delete_credential', methods=['GET'])
def delete_credential():
    credential_id = request.args.get('credential_id')
    return credential_api.delete_credential(credential_id)

@app.route('/set_default_credential', methods=['GET'])
def set_default_credential():
    credential_id = request.args.get('credential_id')
    return credential_api.set_default_credential(credential_id)


@app.route('/register_storage_config', methods=['POST'])
def register_storage_config():
    json = request.get_json()
    name = json['name']
    config = json['config']

    return storage_api.RegisterStorageConfig(name, config)

@app.route('/retreive_storage_config', methods=['GET'])
def retreive_storage_config():
    id = request.args.get('storage_id')

    return storage_api.RetrieveStorageConfig(id)

@app.route('/delete_storage_config', methods=['GET'])
def delete_storage_config():
    id = request.args.get('storage_id')
    deleteCredentials = request.args.get('delete_credentials') == 'true'
    return storage_api.DeleteStorageConfig(id, deleteCredentials)

@app.route('/list_storage_configs', methods=['GET'])
def list_storage_configs():
    return storage_api.ListStorageConfigs()


if __name__ == '__main__':
    app.run()