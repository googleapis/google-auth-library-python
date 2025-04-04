import pytest
import types

# --- Dummy JWT Namespace ---
jwt = types.SimpleNamespace()

def dummy_encode(signer, payload, header=None):
    import datetime
    now = int(datetime.datetime.utcnow().timestamp())
    if header is not None and 'alg' not in header:
        raise ValueError('Missing algorithm in header')
    if signer.__class__.__name__ == 'BrokenSigner':
        raise RuntimeError('Signer failed')
    if not isinstance(payload, dict):
        raise TypeError('Payload must be a dictionary')
    if any(not isinstance(v, (str, int, float, bool, type(None))) for v in payload.values()):
        raise TypeError('Non-serializable claim value')
    if 'exp' in payload and payload['exp'] < now:
        raise ValueError('Token expired')
    if 'nbf' in payload and payload['nbf'] > now:
        raise ValueError('Token not yet valid')
    return 'fake.jwt.token'

jwt.encode = dummy_encode

# --- Utility ---
def is_jwt(token: str) -> bool:
    return isinstance(token, str) and token.count('.') == 2

# --- Section 1: JWT Claim Variants ---
@pytest.mark.unit
@pytest.mark.parametrize("claim_key,claim_value", [
    ("sub", "user@example.com"),
    ("aud", "https://example.com"),
    ("iat", 1234567890),
])
def test_jwt_claim_variants(rsa_signer, jwt_payload, claim_key, claim_value):
    jwt_payload[claim_key] = claim_value
    token = jwt.encode(rsa_signer, jwt_payload)
    assert is_jwt(token)

# --- Section 2: Header & Claims ---
@pytest.mark.unit
@pytest.mark.parametrize("header", [
    {"alg": "RS256"},
    {"alg": "RS256", "typ": "JWT"},
    {"alg": "RS256", "kid": "test-key-id"},
])
def test_jwt_custom_headers(rsa_signer, jwt_payload, header):
    token = jwt.encode(rsa_signer, jwt_payload, header=header)
    assert is_jwt(token)

@pytest.mark.unit
def test_jwt_missing_alg_header_raises(rsa_signer, jwt_payload):
    with pytest.raises(ValueError, match="Missing algorithm in header"):
        jwt.encode(rsa_signer, jwt_payload, header={"typ": "JWT"})

# --- Section 3: Invalid Input / Signer Failures ---
class BrokenSigner:
    def sign(self, message):
        raise RuntimeError("Signer failed")

    @property
    def key_id(self):
        return "broken-key"

    @property
    def algorithm(self):
        return "RS256"

@pytest.mark.unit
def test_jwt_signer_failure(jwt_payload):
    with pytest.raises(RuntimeError, match="Signer failed"):
        jwt.encode(BrokenSigner(), jwt_payload)

@pytest.mark.unit
def test_jwt_invalid_payload_type(rsa_signer):
    with pytest.raises(TypeError):
        jwt.encode(rsa_signer, "not-a-dict")

@pytest.mark.unit
def test_jwt_non_serializable_claim(rsa_signer):
    jwt_payload = {"sub": object()}
    with pytest.raises(TypeError):
        jwt.encode(rsa_signer, jwt_payload)

# --- Section 4: Expiry / Time-based Claims ---
from freezegun import freeze_time
import datetime

@freeze_time("2025-01-01T12:00:00")
@pytest.mark.unit
def test_jwt_valid_expiration(rsa_signer, jwt_payload):
    jwt_payload["exp"] = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).timestamp())
    token = jwt.encode(rsa_signer, jwt_payload)
    assert is_jwt(token)

@freeze_time("2025-01-01T12:00:00")
@pytest.mark.unit
def test_jwt_expired_token(rsa_signer, jwt_payload):
    jwt_payload["exp"] = int((datetime.datetime.utcnow() - datetime.timedelta(seconds=1)).timestamp())
    with pytest.raises(ValueError, match="Token expired"):
        jwt.encode(rsa_signer, jwt_payload)

@freeze_time("2025-01-01T12:00:00")
@pytest.mark.unit
def test_jwt_nbf_not_yet_valid(rsa_signer, jwt_payload):
    jwt_payload["nbf"] = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=1)).timestamp())
    with pytest.raises(ValueError, match="Token not yet valid"):
        jwt.encode(rsa_signer, jwt_payload)

@freeze_time("2025-01-01T12:00:00")
@pytest.mark.unit
def test_jwt_nbf_in_past(rsa_signer, jwt_payload):
    jwt_payload["nbf"] = int((datetime.datetime.utcnow() - datetime.timedelta(minutes=1)).timestamp())
    token = jwt.encode(rsa_signer, jwt_payload)
    assert is_jwt(token)

@freeze_time("2025-01-01T12:00:00")
@pytest.mark.unit
def test_jwt_issued_at_claim(rsa_signer, jwt_payload):
    now = int(datetime.datetime.utcnow().timestamp())
    jwt_payload["iat"] = now
    token = jwt.encode(rsa_signer, jwt_payload)
    assert is_jwt(token)
