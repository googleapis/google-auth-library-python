import pytest

class FakeRSASigner:
    def sign(self, message):
        return b'signed-message'

    @property
    def key_id(self):
        return "fake-key-id"

    @property
    def algorithm(self):
        return "RS256"

@pytest.fixture
def rsa_signer():
    return FakeRSASigner()

@pytest.fixture
def jwt_payload():
    return {
        "sub": "user@example.com",
        "aud": "https://service.example.com",
        "iat": 1234567890
    }
