
import asyncio
import os
import logging
import google.auth
import google.auth.transport.requests
from google.auth.aio.transport.sessions import AsyncAuthorizedSession
from google.auth.aio.credentials import Credentials as AioCredentials

# Configure logging to see detailed mTLS info if available
logging.basicConfig(level=logging.INFO)

class SyncToAsyncCredentialsAdapter(AioCredentials):
    """
    Adapts synchronous google.oauth2.credentials.Credentials to 
    google.auth.aio.credentials.Credentials.
    
    This allows using standard ADC (User Credentials) with AsyncAuthorizedSession.
    It uses a thread executor to perform blocking refresh operations.
    """
    def __init__(self, sync_creds):
        super().__init__()
        self._sync_creds = sync_creds
        
    async def refresh(self, request):
        # We ignore the async `request` passed here and use a new sync Request
        # because the underlying credentials are synchronous.
        sync_request = google.auth.transport.requests.Request()
        await asyncio.to_thread(self._sync_creds.refresh, sync_request)
        self.token = self._sync_creds.token
        self.expiry = self._sync_creds.expiry

    async def before_request(self, request, method, url, headers):
        sync_request = google.auth.transport.requests.Request()
        # Offload the blocking refresh/apply check to a thread
        await asyncio.to_thread(
            self._sync_creds.before_request, sync_request, method, url, headers
        )
        # after before_request, token might be refreshed
        self.token = self._sync_creds.token
        self.expiry = self._sync_creds.expiry

async def main():
    # 1. Get default credentials and project
    print("Loading default credentials...")
    sync_credentials, project_id = google.auth.default(
        scopes=["https://www.googleapis.com/auth/pubsub"]
    )

    print(f"Using credentials for project: {project_id}")
    print(f"Credential type: {type(sync_credentials)}")

    if not project_id:
        print("Error: Could not determine project ID from environment.")
        print("Please set GOOGLE_CLOUD_PROJECT or have it in your ADC.")
        return

    # 2. Adapt credentials
    async_credentials = SyncToAsyncCredentialsAdapter(sync_credentials)

    # 3. Create the AsyncAuthorizedSession
    session = AsyncAuthorizedSession(async_credentials)

    try:
        # 4. Enable mTLS
        # To actually force mTLS, ensure GOOGLE_API_USE_CLIENT_CERTIFICATE=true is in env
        print("Configuring mTLS channel...")
        await session.configure_mtls_channel()
        
        print(f"mTLS enabled: {session.is_mtls}")

        # 5. Make a request to Pub/Sub API
        url = f"https://pubsub.googleapis.com/v1/projects/{project_id}/topics"
        print(f"Making request to: {url}")
        
        response = await session.get(url)
        
        print(f"Response Status: {response.status_code}")
        if response.status_code == 200:
            response_data = await response.json()
            print("Success! Topics found.")
            # print("Response Body (first 200 chars):", str(response_data)[:200])
        else:
            print("Request failed.")
            print(await response.text())

    finally:
        await session.close()

if __name__ == "__main__":
    # Ensure SSL cert/key env vars are set if you want to test actual mTLS,
    # otherwise it might fallback to regular TLS if the check returns False.
    if os.environ.get("GOOGLE_API_USE_CLIENT_CERTIFICATE") != "true":
        print("WARNING: GOOGLE_API_USE_CLIENT_CERTIFICATE is not set to 'true'.")
        print("mTLS might not be attempted. Run with: export GOOGLE_API_USE_CLIENT_CERTIFICATE=true")
    
    asyncio.run(main())
