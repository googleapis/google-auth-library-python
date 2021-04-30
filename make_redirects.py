# Copyright 2021 Google LLC
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

import requests

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from pathlib import Path


def get_files_with_extension(dirName, extension=".html"):
    files = []

    for file in Path(dirName).glob(f"**/*{extension}"):
        if file.suffix == extension:
            files.append(str(file))

    return files


def add_redirect(path, url):
    HTML_TEMPLATE = f"""<html>
<head>
 <meta http-equiv="refresh" content="1; url={url}" />
 <script>
   window.location.href = "{url}"
 </script>
</head>
</html>
"""
    with open(path, "w") as f:
        f.write(HTML_TEMPLATE)


def add_redirect_to_md(path, url):
    MD_TEMPLATE = f"""---
redirect_to: "{url}"
---
"""
    with open(path, "w") as f:
        f.write(MD_TEMPLATE)


def make_redirects(dirname, ext=".html"):
    """
	Assembles a dictionary where key is file path and value is the googleapis.dev url
    Returns the dictionary and a list of paths for which a redirect
    could not be determined.
	"""
    GOOGLEAPIS_AUTH_ROOT = "https://googleapis.dev/python/google-auth/latest"
    redirects = {}

    html_files = get_files_with_extension(dirname, extension=ext)
    print(f"{len(html_files)} files found in '{dirname}'.")
    for file in html_files:
        if "module" in file:
            # Pages under _modules are source code.
            # Redirect them to the api top level page.
            redirects[file] = f"{GOOGLEAPIS_AUTH_ROOT}/index.html"
        else:
            # Pages with reference documentation.
            redirects[file] = f"{GOOGLEAPIS_AUTH_ROOT}/{file}"

    return redirects


if __name__ == "__main__":
    redirects = make_redirects(".")

    retry_strategy = Retry(total=3,)
    adapter = HTTPAdapter(max_retries=retry_strategy)
    http = requests.Session()
    http.mount("https://", adapter)
    http.mount("http://", adapter)

    for path, url in redirects.items():
        print(url)
        resp = http.get(url)
        if resp.status_code == 200:
            add_redirect(path, url)
        else:
            print(f"404: {url}")
