import pytest
from google.auth.constraints import Constraints

def test_allow_none():
    constraints = Constraints()
    assert constraints.isValid({"type": "authorized_user"}) == False
    assert constraints.isValid({"type": "service_account"}) == False
    assert constraints.isValid({"type": "external_account"}) == False
    assert constraints.isValid({"type": "impersonated_service_account"}) == False


def test_allow_all():
    constraints = Constraints(allow_types="all")
    assert constraints.isValid({"type": "authorized_user"}) == True
    assert constraints.isValid({"type": "service_account"}) == True
    assert constraints.isValid({"type": "external_account"}) == True
    assert constraints.isValid({"type": "impersonated_service_account"}) == True


def test_allow_specific_types():
    constraints = Constraints(allow_types = ["service_account", "external_account"])
    assert len(constraints._validators) == 2  # Correct validators instantiated?

    #Check if the allowed types are valid
    assert constraints.isValid({"type": "authorized_user"}) is False
    assert constraints.isValid({"type": "service_account"}) is True
    assert constraints.isValid({"type": "external_account", "token_url": "https://sts.googleapis.com/v1/token"}) is True

    # Check with a different universe domain
    constraints = Constraints(allow_types=["external_account"], universe_domain="example.com")
    assert constraints.isValid({"type": "external_account", "token_url": "https://sts.googleapis.com/v1/token"}) is False
    assert constraints.isValid({"type": "external_account", "token_url": "https://sts.example.com/v1/token"}) is True
    
    # Check for impersonated service account
    constraints = Constraints(allow_types=["impersonated_service_account"], universe_domain="example.com")

    assert constraints.isValid({
        "type": "impersonated_service_account",
        "service_account_impersonation_url": "https://iamcredentials.example.com/v1/projects/-/serviceAccounts/svc_acc@developer.gserviceaccount.com:generateAccessToken"
    }) == True

    assert constraints.isValid({
        "type": "impersonated_service_account",
        "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc_acc@developer.gserviceaccount.com:generateAccessToken"
    }) == False

    constraints = Constraints(allow_types=["gdch_service_account"])

    assert constraints.isValid({"type": "gdch_service_account"}) == True
    assert constraints.isValid({"type": "service_account"}) == False




def test_invalid_allow_types():
    with pytest.raises(ValueError) as excinfo:
        Constraints(allow_types="invalid") # Type error: not a list
    assert "Invalid allow_types argument" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        Constraints(allow_types=["invalid_type"]) # Invalid credential type
    assert "Invalid credential type: invalid_type" in str(excinfo.value)

