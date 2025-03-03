# example for getting the default credentials
import google.auth
import google.auth.transport.requests

cred, project = google.auth.default(scopes=["email"]) # create an object, but it doesn't token yet

print(cred)
print(project)

req = google.auth.transport.requests.Request()  # create a http object for http calls
cred.refresh(req)  # call refresh to fetch a token

print(cred.token)
print(cred.expiry)