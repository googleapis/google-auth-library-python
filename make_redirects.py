import requests

static_html_pages = [
    "search.html",
    "genindex.html",
    "py-modindex.html",
    "user-guide.html",
    "index.html",
    "oauth2client-deprecation.html",
    "_modules/abc.html",
    "_modules/index.html",
    "_modules/urllib3/request.html",
    "_modules/aiohttp/client.html",
    "_modules/requests/sessions.html",
    "_modules/google/oauth2/utils.html",
    "_modules/google/oauth2/_service_account_async.html",
    "_modules/google/oauth2/_credentials_async.html",
    "_modules/google/oauth2/sts.html",
    "_modules/google/oauth2/credentials.html",
    "_modules/google/oauth2/id_token.html",
    "_modules/google/oauth2/service_account.html",
    "_modules/google/auth/_credentials_async.html",
    "_modules/google/auth/identity_pool.html",
    "_modules/google/auth/transport.html",
    "_modules/google/auth/app_engine.html",
    "_modules/google/auth/_jwt_async.html",
    "_modules/google/auth/_default.html",
    "_modules/google/auth/iam.html",
    "_modules/google/auth/jwt.html",
    "_modules/google/auth/impersonated_credentials.html",
    "_modules/google/auth/exceptions.html",
    "_modules/google/auth/aws.html",
    "_modules/google/auth/credentials.html",
    "_modules/google/auth/external_account.html",
    "_modules/google/auth/compute_engine/credentials.html",
    "_modules/google/auth/transport/urllib3.html",
    "_modules/google/auth/transport/grpc.html",
    "_modules/google/auth/transport/_aiohttp_requests.html",
    "_modules/google/auth/transport/mtls.html",
    "_modules/google/auth/transport/requests.html",
    "_modules/google/auth/crypt/_python_rsa.html",
    "_modules/google/auth/crypt/base.html",
    "reference/google.auth.credentials.html",
    "reference/google.auth.jwt.html",
    "reference/google.auth.crypt.html",
    "reference/google.oauth2._credentials_async.html",
    "reference/google.auth.exceptions.html",
    "reference/google.auth.iam.html",
    "reference/google.oauth2.sts.html",
    "reference/google.oauth2.utils.html",
    "reference/google.auth.aws.html",
    "reference/google.auth.compute_engine.credentials.html",
    "reference/google.auth.transport._aiohttp_requests.html",
    "reference/google.auth.impersonated_credentials.html",
    "reference/modules.html",
    "reference/google.html",
    "reference/google.auth.crypt.base.html",
    "reference/google.oauth2.service_account.html",
    "reference/google.oauth2.credentials.html",
    "reference/google.oauth2._service_account_async.html",
    "reference/google.auth.app_engine.html",
    "reference/google.auth.transport.requests.html",
    "reference/google.auth._jwt_async.html",
    "reference/google.auth.external_account.html",
    "reference/google.auth.transport.urllib3.html",
    "reference/google.auth.transport.mtls.html",
    "reference/google.auth.html",
    "reference/google.auth._credentials_async.html",
    "reference/google.auth.identity_pool.html",
    "reference/google.oauth2.id_token.html",
    "reference/google.auth.crypt.rsa.html",
    "reference/google.auth.crypt.es256.html",
    "reference/google.auth.compute_engine.html",
    "reference/google.auth.environment_vars.html",
    "reference/google.oauth2.html",
    "reference/google.auth.transport.html",
    "reference/google.auth.transport.grpc.html",
]

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

    for path, url in redirects.items():
        resp = requests.get(url)
        if resp.status_code == 200:
            add_redirect(path, url)
        else:
            print(f"404: {url}")
