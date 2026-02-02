# Copyright 2024 Google LLC
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
import ssl
import unittest
from unittest import mock
import asyncio
import json

from google.auth.aio.transport import mtls
from google.auth import exceptions
from google.auth import environment_vars

class TestMtls(unittest.TestCase):

    @mock.patch("ssl.create_default_context")
    def test_make_client_cert_ssl_context(self, create_default_context):
        mock_context = mock.Mock()
        create_default_context.return_value = mock_context
        
        cert_bytes = b"cert_content"
        key_bytes = b"key_content"
        passphrase = b"passphrase"
        
        context = mtls.make_client_cert_ssl_context(cert_bytes, key_bytes, passphrase)
        
        # Verify context creation
        create_default_context.assert_called_once_with(ssl.Purpose.SERVER_AUTH)
        assert context == mock_context
        
        # Verify load_cert_chain was called with some file paths
        mock_context.load_cert_chain.assert_called_once()
        call_args = mock_context.load_cert_chain.call_args
        cert_path = call_args[1]['certfile']
        key_path = call_args[1]['keyfile']
        password = call_args[1]['password']
        
        # Verify passphrase passed correctly
        self.assertEqual(password, passphrase)
        
        # Verify temporary files provided but deleted after call returns
        self.assertFalse(os.path.exists(cert_path))
        self.assertFalse(os.path.exists(key_path))

    @mock.patch("ssl.create_default_context")
    def test_make_client_cert_ssl_context_error(self, create_default_context):
        mock_context = mock.Mock()
        create_default_context.return_value = mock_context
        
        # Simulate SSL error
        mock_context.load_cert_chain.side_effect = ssl.SSLError("oops")
        
        with self.assertRaises(exceptions.TransportError):
            mtls.make_client_cert_ssl_context(b"cert", b"key")

if __name__ == '__main__':
    unittest.main()
