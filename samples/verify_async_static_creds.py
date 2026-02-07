
import asyncio
import os
import google
from google.auth.aio.credentials import StaticCredentials
from google.auth.aio.transport.sessions import AsyncAuthorizedSession

async def main():
    # 1. Obtain a token from ADC
    # We use sync credentials to get the token, then pass it to StaticCredentials
    # which is compatible with AsyncAuthorizedSession.
    from google.auth.transport.requests import Request
    import google.auth

    print("Loading default credentials...")
    creds, project_id = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    
    # Refresh to ensure we have a valid token
    print("Refreshing credentials to get access token...")
    creds.refresh(Request())
    token = creds.token
    
    print(f"Using token from ADC: {token[:10]}...")

    # 2. Create StaticCredentials
    # These credentials are immutable and will not be refreshed by the Async session.
    # Since we just refreshed them, they should be valid for ~1 hour.
    async_creds = StaticCredentials(token=token)

    # 3. Create the AsyncAuthorizedSession
    session = AsyncAuthorizedSession(async_creds)

    try:
        # 4. Make a request to Pub/Sub API (REST)
        # Note: GAPIC libraries (google-cloud-pubsub) generally do not support 
        # google.auth.aio credentials yet. We use REST to verify the Async Session.
        url = f"https://pubsub.googleapis.com/v1/projects/{project_id}/topics"
        print(f"Making request to: {url}")

        response = await session.get(url)
        print(f"Response Status: {response.status_code}")
        
        if response.status_code == 200:
            import json
            body_bytes = await response.read()
            data = json.loads(body_bytes)
            print("Topics found (count):", len(data.get("topics", [])))

        else:
            print("Request failed.")
            print((await response.read()).decode("utf-8"))

    finally:
        await session.close()

if __name__ == "__main__":
    asyncio.run(main())
