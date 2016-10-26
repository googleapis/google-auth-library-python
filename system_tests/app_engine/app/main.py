# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib
import sys
from StringIO import StringIO
import traceback

from google.appengine.api import app_identity
import google.auth
from google.auth import app_engine
import google.auth.transport.urllib3
import urllib3.contrib.appengine
import webapp2


http = urllib3.contrib.appengine.AppEngineManager()
http_request = google.auth.transport.urllib3.Request(http)


def test_credentials():
    credentials = app_engine.Credentials()
    scoped_credentials = credentials.with_scopes([
        'https://www.googleapis.com/auth/userinfo.email'])

    scoped_credentials.refresh(None)

    assert scoped_credentials.valid
    assert scoped_credentials.token is not None


def test_default():
    credentials, project_id = google.auth.default()

    assert isinstance(credentials, app_engine.Credentials)
    assert project_id == app_identity.get_application_id()


@contextlib.contextmanager
def capture():
    """Context manager that captures stderr and stdout."""
    oldout, olderr = sys.stdout, sys.stderr
    try:
        out = StringIO()
        sys.stdout, sys.stderr = out, out
        yield out
    finally:
        sys.stdout, sys.stderr = oldout, olderr


def run_tests():
    """Runs all tests.

    Returns:
        Tuple[bool, str]: A tuple containing True if all tests pass, False
        otherwise, and any captured output from the tests.
    """
    status = False
    output = ''

    with capture() as capsys:
        try:
            test_credentials()
            test_default()
            status = True
        except Exception:
            status = False
            output = 'Stacktrace:\n{}\n'.format(traceback.format_exc())

    output += 'Captured output:\n{}'.format(capsys.getvalue())
    return status, output


class MainHandler(webapp2.RequestHandler):
    def get(self):
        self.response.headers['content-type'] = 'text/plain'

        status, output = run_tests()

        if not status:
            self.response.status = 500

        self.response.write(output)


app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
