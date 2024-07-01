import google.auth


cred, _ = google.auth.default()
print(cred.get_cred_info())