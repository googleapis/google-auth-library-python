import asyncio
import json
import google.auth
from google.auth.transport.requests import Request
from google.auth.aio.credentials import StaticCredentials
from google.auth.aio.transport.sessions import AsyncAuthorizedSession
from google.auth.credentials import Credentials

async def get_creds_async() -> tuple[Credentials, str]:
    """Loads default credentials asynchronously."""
    print("Loading default credentials asynchronously...")
    # Run the potentially blocking google.auth.default() in a separate thread.
    creds, project_id = await asyncio.to_thread(
        google.auth.default, scopes=["https://www.googleapis.com/auth/pubsub"]
    )
    return creds, project_id

async def refresh_creds_if_needed_async(creds: Credentials) -> str:
    """Refreshes credentials asynchronously only if expired or token is missing."""
    if not creds:
        raise ValueError("Credentials object is None.")

    if creds.expired or not creds.token:
        print("Credentials expired or token missing, refreshing asynchronously...")
        # Run the potentially blocking creds.refresh() in a separate thread
        # to avoid blocking the event loop.
        await asyncio.to_thread(creds.refresh, Request())
        print("Credentials refreshed.")
    else:
        print("Credentials are valid, no refresh needed.")

    if not creds.token:
        raise RuntimeError("Failed to get token after refresh.")
    return creds.token

async def main():
    try:
        # 1. Obtain credentials asynchronously
        creds, project_id = await get_creds_async()

        # 2. Refresh token if necessary, asynchronously
        token = await refresh_creds_if_needed_async(creds)
        print(f"Using token: {token[:10]}...")

        # 3. Create StaticCredentials for the async session
        # StaticCredentials are used because AsyncAuthorizedSession expects
        # credentials designed for async environments. Since we handle the
        # refresh manually before this, we provide the static token.
        async_creds = StaticCredentials(token=token)

        # 4. Create the AsyncAuthorizedSession
        session = AsyncAuthorizedSession(async_creds)

        try:
            # Attempt to configure mTLS channel
            await session.configure_mtls_channel()
            print("mTLS channel configured.")

            # 5. Make a request to Pub/Sub API (REST) using the mTLS endpoint
            url = f"https://pubsub.googleapis.com/v1/projects/{project_id}/topics"
            print(f"Making request to: {url}")

            response = await session.request(
                'GET', 'https://pubsub.googleapis.com/v1/projects/caa-eg-cloudsdk/topics')
            print(f"Response Status: {response.status_code}")
            body_bytes = await response.read()
            body = body_bytes.decode("utf-8")

            if response.status_code == 200:
                data = json.loads(body)
                print("Topics found (count):", len(data.get("topics", [])))
            else:
                print("Request failed.")
                print("Response Body:", body)

        finally:
            await session.close()
            print("Session closed.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    asyncio.run(main())
