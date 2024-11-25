from google.auth import default
from google.auth.transport.requests import Request
from google.auth import impersonated_credentials
import google.oauth2.id_token

request = google.auth.transport.requests.Request()
target_audience = "https://pubsub.googleapis.com"
scopes = ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/iam']
message = b"This message is top secret!"

output_file = "python_wf_headless.txt"  # Specify the output file name

with open(output_file, "w") as f:
    # Get access token
    try:
        cred, _ = default(scopes=scopes)
        f.write(f"Credential Type: {type(cred)}\n")

        cred.refresh(request)
        access_token = cred.token
        f.write(f"Access token: {access_token}\n")

        # Test Signing
        try:
            # Use the credentials to create a signer object
            signer = google.auth.iam.Signer(request, cred, "libraries-sa@bootstrap-libraries.tpczero-system.iam.gserviceaccount.com ")

            # Sign the message
            signature = signer.sign(message)

            f.write(f"Signature: {signature.hex()}\n")

        except Exception as e:
            f.write(f"Error signing message: {e}\n")

        # Test impersonation
        try:
            target_scopes = scopes
            impersonated_cred = impersonated_credentials.Credentials(
                source_credentials=cred,
                target_principal='libraries-sa@bootstrap-libraries.tpczero-system.iam.gserviceaccount.com',
                target_scopes=target_scopes,
                lifetime=500
            )

            # Test impersonated access token 
            try:
                impersonated_cred.refresh(request)
                impersonated_access_token = impersonated_cred.token
                f.write(f"Impersonated access token: {impersonated_access_token}\n\n")
            except Exception as e:
                f.write(f"Error getting impersonated access token: {e}\n\n")

            # Test impersonated ID token
            try:
                id_impersonated_credentials = impersonated_credentials.IDTokenCredentials(
                    impersonated_cred, target_audience)
                id_impersonated_credentials.refresh(request)
                id_impersonated_token = id_impersonated_credentials.token
                f.write(f"ID impersonated token: {id_impersonated_token}\n\n")
            except Exception as e:
                f.write(f"Error getting impersonated ID token: {e}\n\n")

            # Test signing with impersonated cred
            try:
                signature = impersonated_cred.sign_bytes(message)
                f.write(f"Signature: {signature.hex()}\n")
            except Exception as e:
                f.write(f"Error signing message with impersoanted cred: {e}\n")

        except Exception as e:
            f.write(f"Error creating impersonated cred: {e}\n\n")
    except Exception as e:
        f.write(f"Error getting access token: {e}\n\n")

    # Test ID token
    try:

        # Create ID token credentials.
        id_credentials = google.oauth2.id_token.fetch_id_token_credentials(target_audience, request=request)
        f.write(f"ID Credential Type: {type(id_credentials)}\n\n")
        # Refresh the credential to obtain an ID token.
        id_credentials.refresh(request)

        id_token = id_credentials.token
        id_token_expiry = id_credentials.expiry
        token2 = google.oauth2.id_token.verify_token(id_token, request=request, is_jwk_key=False, audience=target_audience, certs_url="https://www.googleapis.com/oauth2/v1/certs")
        token3 = google.oauth2.id_token.verify_token(id_token, request=request, is_jwk_key=True, audience=target_audience, certs_url="https://www.googleapis.com/oauth2/v3/certs")
        eq = token2 == token3
        f.write(f"ID token verify: {eq}")
    except Exception as e:
        f.write(f"Error getting ID token: {e}")