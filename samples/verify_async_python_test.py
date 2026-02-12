"""Python example test for CBA."""

import asyncio
import json
import google.auth
from google.auth.transport.requests import Request
from google.auth.aio.credentials import StaticCredentials
from google.auth.aio.transport.sessions import AsyncAuthorizedSession
from google.auth.credentials import Credentials

  # Obtain Application Default Credentials (ADC) with the specified scopes
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
    # Create an authorized HTTP session using the ADC credentials
    creds, project_id = await get_creds_async()
    token = await refresh_creds_if_needed_async(creds)
    async_creds = StaticCredentials(token=token)
    session = AsyncAuthorizedSession(async_creds)

    # Configure the session to use mTLS. This is not needed if using a python API
    # client library, but is required when using the HTTP session directly.
    await session.configure_mtls_channel()  # Requires PyOpenSSL to be installed
    print(f"DEBUG: Session is_mtls = {session.is_mtls}")
    try:
        # Make a GET request to the Pub/Sub API endpoint
        response = await session.get( 
            "https://pubsub.mtls.googleapis.com/v1/projects/caa-eg-cloudsdk/topics")

        # Check if the request was successful

        # Log the response status and content
        print(f"Status: {response.status_code}")
        print(f"Request URL: {response.headers}")
    except Exception as e:
        print(f"Error making the request: {e}")


if __name__ == "__main__":
    asyncio.run(main())
