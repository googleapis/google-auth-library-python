from google.auth.transport.requests import Request, AuthorizedSession
from google.oauth2 import service_account, id_token
from typing import Optional


class GoogleAuthLite:
    def __init__(self, service_account_file: str, scopes: Optional[list[str]] = None):
        self.scopes = scopes or ["https://www.googleapis.com/auth/cloud-platform"]
        self.credentials = service_account.Credentials.from_service_account_file(
            service_account_file, scopes=self.scopes
        )
        self.session = AuthorizedSession(self.credentials)

    def ensure_valid_token(self):
        if not self.credentials.valid or self.credentials.expired:
            self.credentials.refresh(Request())

    def get_access_token(self) -> str:
        self.ensure_valid_token()
        return self.credentials.token

    def get_id_token(self, target_audience: str) -> str:
        return id_token.fetch_id_token(Request(), target_audience)

    def get(self, url: str, **kwargs):
        self.ensure_valid_token()
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs):
        self.ensure_valid_token()
        return self.session.post(url, **kwargs)

    def put(self, url: str, **kwargs):
        self.ensure_valid_token()
        return self.session.put(url, **kwargs)

    def delete(self, url: str, **kwargs):
        self.ensure_valid_token()
        return self.session.delete(url, **kwargs)

    def request(self, method: str, url: str, **kwargs):
        self.ensure_valid_token()
        return self.session.request(method, url, **kwargs)
