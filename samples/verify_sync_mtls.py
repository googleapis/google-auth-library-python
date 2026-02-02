
import os
import google.auth
import google.auth.transport.requests
from google.auth.transport.requests import AuthorizedSession

def main():
    # 1. Get default credentials and project
    print("Loading default credentials...")
    credentials, project_id = google.auth.default(
        scopes=["https://www.googleapis.com/auth/pubsub"]
    )

    print(f"Using credentials for project: {project_id}")
    print(f"Credential type: {type(credentials)}")

    if not project_id:
        print("Error: Could not determine project ID from environment.")
        return

    # 2. Create the AuthorizedSession
    session = AuthorizedSession(credentials)

    # 3. Enable mTLS
    # To actually force mTLS, ensure GOOGLE_API_USE_CLIENT_CERTIFICATE=true is in env
    print("Configuring mTLS channel...")
    session.configure_mtls_channel()
    
    print(f"mTLS enabled: {session.is_mtls}")

    # 4. Make a request to Pub/Sub API
    url = f"https://pubsub.googleapis.com/v1/projects/{project_id}/topics"
    print(f"Making request to: {url}")
    
    response = session.get(url)
    
    print(f"Response Status: {response.status_code}")
    if response.status_code == 200:
        print("Success! Topics found.")
    else:
        print("Request failed.")
        print(response.text)

if __name__ == "__main__":
    if os.environ.get("GOOGLE_API_USE_CLIENT_CERTIFICATE") != "true":
        print("WARNING: GOOGLE_API_USE_CLIENT_CERTIFICATE is not set to 'true'.")
    
    main()
