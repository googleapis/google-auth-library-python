
import asyncio
import os
import vertexai
from google.auth.transport.requests import Request
import google.auth
from google.auth.aio.credentials import StaticCredentials
from vertexai.preview.generative_models import GenerativeModel
from google.cloud import aiplatform

async def main():
    print("Loading default credentials...")
    creds, project_id = google.auth.default()
    
    # Refresh to ensure we have a valid token
    print("Refreshing credentials to get access token...")
    creds.refresh(Request())
    token = creds.token
    print(f"Using token from ADC: {token[:10]}...")

    # Create StaticCredentials for Async
    async_creds = StaticCredentials(token=token)

    # Initialize Vertex AI with REST transport
    print(f"Initializing Vertex AI for project: {project_id}")
    vertexai.init(project=project_id, location="us-central1", api_transport="rest")
    
    # Inject our Async Credentials
    # This uses the hidden API mentioned by the user to set the async REST credentials
    print("Injecting async credentials into AI Platform initializer...")
    aiplatform.initializer._set_async_rest_credentials(credentials=async_creds)

    # Generate Content
    print("Generating content...")
    model = GenerativeModel("gemini-2.5-flash")
    
    try:
        response = await model.generate_content_async("Tell me a one sentence joke.")
        print("\nResponse from Gemini:")
        print(response.text)
    except Exception as e:
        print(f"\nError generating content: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
