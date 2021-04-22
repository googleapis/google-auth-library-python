import google.auth._default_async
import google.auth.transport._aiohttp_requests
import os
import asyncio

scopes = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/appengine.admin",
    "https://www.googleapis.com/auth/compute",
    "https://www.googleapis.com/auth/accounts.reauth",
]
req = google.auth.transport._aiohttp_requests.Request()
creds, _ = google.auth._default_async._get_gcloud_sdk_credentials()
creds._scopes = scopes

loop = asyncio.get_event_loop()
result = loop.run_until_complete(asyncio.gather(creds.refresh(req)))
loop.close()
