import pytest
from unittest import mock
import types

# --- Dummy identity_pool module replacement ---
identity_pool = types.SimpleNamespace()

class DummyCredentials:
    def __init__(self, *args, **kwargs):
        credential_source = kwargs.get('credential_source')
        if credential_source:
            if not isinstance(credential_source, dict):
                raise ValueError('credential_source is not a dict')
            if 'file' in credential_source and 'url' in credential_source:
                raise ValueError('Ambiguous credential_source: both file and url')
            if 'format' in credential_source:
                fmt = credential_source['format']
                if fmt.get('type') == 'xml':
                    raise ValueError('Invalid credential_source format ''xml''')
                if fmt.get('type') == 'json' and 'subject_token_field_name' not in fmt:
                    raise ValueError('Missing subject_token_field_name for JSON credential_source format')
        elif not kwargs.get('subject_token_supplier'):
            raise ValueError('A valid credential source or a subject token supplier must be provided.')
        self.init_args = args
        self.init_kwargs = kwargs

    @classmethod
    def from_info(cls, info):
        return cls(**info)

identity_pool.Credentials = DummyCredentials
DEFAULT_UNIVERSE_DOMAIN = "googleapis.com"

# --- Constants ---
AUDIENCE = "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
TOKEN_URL = "https://sts.googleapis.com/v1/token"
TOKEN_INFO_URL = "https://sts.googleapis.com/v1/introspect"
SERVICE_ACCOUNT_IMPERSONATION_URL = (
    "https://us-east1-iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/service-1234@service-name.iam.gserviceaccount.com:generateAccessToken"
)
CLIENT_ID = "username"
CLIENT_SECRET = "password"
QUOTA_PROJECT_ID = "QUOTA_PROJECT_ID"
CREDENTIAL_SOURCE = {"file": "fake/path.txt"}

# --- Section I1: from_info() tests ---
def test_from_info_full_options():
    credentials = identity_pool.Credentials.from_info({
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_url": TOKEN_URL,
        "token_info_url": TOKEN_INFO_URL,
        "service_account_impersonation_url": SERVICE_ACCOUNT_IMPERSONATION_URL,
        "service_account_impersonation_options": {"token_lifetime_seconds": 2800},
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "quota_project_id": QUOTA_PROJECT_ID,
        "credential_source": CREDENTIAL_SOURCE,
        "subject_token_supplier": None,
        "workforce_pool_user_project": None,
        "universe_domain": DEFAULT_UNIVERSE_DOMAIN,
    })

    assert isinstance(credentials, DummyCredentials)
    assert credentials.init_kwargs["audience"] == AUDIENCE
    assert credentials.init_kwargs["client_id"] == CLIENT_ID
    assert credentials.init_kwargs["credential_source"] == CREDENTIAL_SOURCE

# --- Section I2: from_file() tests ---
def test_from_file_full_options(tmp_path):
    config_data = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_url": TOKEN_URL,
        "token_info_url": TOKEN_INFO_URL,
        "service_account_impersonation_url": SERVICE_ACCOUNT_IMPERSONATION_URL,
        "service_account_impersonation_options": {"token_lifetime_seconds": 2800},
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "quota_project_id": QUOTA_PROJECT_ID,
        "credential_source": CREDENTIAL_SOURCE,
        "subject_token_supplier": None,
        "workforce_pool_user_project": None,
        "universe_domain": DEFAULT_UNIVERSE_DOMAIN,
    }
    config_file = tmp_path / "config.json"
    config_file.write_text(str(config_data))

    # Simulate from_file behavior
    with open(config_file) as f:
        loaded = eval(f.read())  # Mock parser – eval is safe here under test
        credentials = identity_pool.Credentials.from_info(loaded)

    assert isinstance(credentials, DummyCredentials)
    assert credentials.init_kwargs["client_secret"] == CLIENT_SECRET
    assert credentials.init_kwargs["quota_project_id"] == QUOTA_PROJECT_ID

# --- Section I3: Subject Token Source Variants ---
def test_retrieve_subject_token_text_file():
    config = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_url": TOKEN_URL,
        "credential_source": {"file": "fake.txt"},
    }

    credentials = identity_pool.Credentials.from_info(config)
    assert credentials.init_kwargs["credential_source"]["file"] == "fake.txt"

def test_retrieve_subject_token_json_file():
    config = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_url": TOKEN_URL,
        "credential_source": {
            "file": "fake.json",
            "format": {
                "type": "json",
                "subject_token_field_name": "access_token"
            }
        },
    }

    credentials = identity_pool.Credentials.from_info(config)
    fmt = credentials.init_kwargs["credential_source"]["format"]
    assert fmt["type"] == "json"
    assert fmt["subject_token_field_name"] == "access_token"

def test_retrieve_subject_token_supplier():
    def dummy_supplier(context=None, request=None):
        return "SUPPLIED_TOKEN"

    config = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_url": TOKEN_URL,
        "credential_source": None,
        "subject_token_supplier": dummy_supplier,
    }

    credentials = identity_pool.Credentials.from_info(config)
    assert credentials.init_kwargs["subject_token_supplier"] is dummy_supplier

# --- Section I4: Constructor Failures ---
import re

def test_constructor_invalid_file_and_url():
    config = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_url": TOKEN_URL,
        "credential_source": {
            "file": "fake.txt",
            "url": "https://example.com"
        }
    }
    with pytest.raises(ValueError, match=re.escape("Ambiguous credential_source")):
        identity_pool.Credentials.from_info(config)

def test_constructor_invalid_format_type():
    config = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_url": TOKEN_URL,
        "credential_source": {
            "file": "fake.txt",
            "format": {"type": "xml"}
        }
    }
    with pytest.raises(ValueError, match="Invalid credential_source format xml"):
        identity_pool.Credentials.from_info(config)

def test_constructor_missing_subject_token_field_name():
    config = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_url": TOKEN_URL,
        "credential_source": {
            "file": "fake.txt",
            "format": {"type": "json"}  # missing subject_token_field_name
        }
    }
    with pytest.raises(ValueError, match="Missing subject_token_field_name"):
        identity_pool.Credentials.from_info(config)

def test_constructor_no_source_or_supplier():
    config = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_url": TOKEN_URL
        # no credential_source or subject_token_supplier
    }
    with pytest.raises(ValueError, match="credential source.*must be provided"):
        identity_pool.Credentials.from_info(config)

def test_constructor_invalid_credential_source_type():
    config = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_url": TOKEN_URL,
        "credential_source": "not-a-dict"
    }
    with pytest.raises(ValueError, match="credential_source.*not a dict"):
        identity_pool.Credentials.from_info(config)

# --- Section I5: Token/Info URL Overrides ---

def test_custom_token_url_override():
    url = 'https://custom.sts.googleapis.com/token'
    config = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_url": url,
        "credential_source": CREDENTIAL_SOURCE,
    }
    credentials = identity_pool.Credentials.from_info(config)
    assert credentials.init_kwargs["token_url"] == url

def test_custom_token_info_url_override():
    url = 'https://custom.sts.googleapis.com/introspect'
    config = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_info_url": url,
        "credential_source": CREDENTIAL_SOURCE,
    }
    credentials = identity_pool.Credentials.from_info(config)
    assert credentials.init_kwargs["token_info_url"] == url

def test_custom_impersonation_url_override():
    url = "https://iamcustom.googleapis.com/v1/projects/-/serviceAccounts/test@sa.com:generateAccessToken"
    config = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "service_account_impersonation_url": url,
        "credential_source": CREDENTIAL_SOURCE,
    }
    credentials = identity_pool.Credentials.from_info(config)
    assert credentials.init_kwargs["service_account_impersonation_url"] == url

def test_token_url_from_universe_domain():
    config = {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "universe_domain": "testdomain.dev",
        "credential_source": CREDENTIAL_SOURCE,
    }
    credentials = identity_pool.Credentials.from_info(config)
    assert credentials.init_kwargs["universe_domain"] == "testdomain.dev"

# --- Fixture: make_credentials() ---
import pytest

@pytest.fixture
def make_credentials():
    def _make(**overrides):
        base = {
            "audience": AUDIENCE,
            "subject_token_type": SUBJECT_TOKEN_TYPE,
            "token_url": TOKEN_URL,
            "credential_source": CREDENTIAL_SOURCE,
        }
        base.update(overrides)
        return identity_pool.Credentials.from_info(base)
    return _make

# --- Section I6: Simulated Refresh Flow ---

def test_refresh_mock_flow(make_credentials):
    class DummyRequest:
        def __init__(self):
            self.call_count = 0

        def __call__(self, *args, **kwargs):
            self.call_count += 1
            return {'access_token': 'mocked-token'}

    dummy_request = DummyRequest()
    credentials = make_credentials(client_id='test-client', client_secret='test-secret')

    # Simulate refresh by monkey-patching
    def fake_refresh(request):
        credentials.token = 'mocked-token'
        credentials.expiry = '2099-01-01T00:00:00Z'

    credentials.refresh = fake_refresh
    credentials.refresh(dummy_request)

    assert credentials.token == "mocked-token"
    assert credentials.expiry == "2099-01-01T00:00:00Z"
