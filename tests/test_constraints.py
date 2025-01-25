import unittest
from google.auth import constraints
from google.auth.constraints import (
    Constraints,
    ExternalAccountValidator,
    ServiceAccountValidator,
    UserAccountValidator,
    ImpersonatedServiceAccountValidator,
    GDCHServiceAccountValidator,
    CredentialConstraintsChoice,
)


class ConstraintsTest(unittest.TestCase):
    def test_allow_everything_insecure(self):
        c = Constraints.allow_everything_insecure()
        self.assertTrue(c.is_valid({"type": "any"}))

    def test_allow_everything_secure(self):
        c = Constraints.allow_everything_secure()

        self.assertTrue(
            c.is_valid(
                {
                    "type": "service_account",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            )
        )
        self.assertTrue(
            c.is_valid(
                {
                    "type": "external_account",
                    "token_url": "https://sts.googleapis.com/v1/token",
                }
            )
        )
        self.assertTrue(
            c.is_valid({"type": "authorized_user"})
        )  # User accounts don't have additional fields to validate

        self.assertFalse(
            c.is_valid({"type": "service_account", "token_uri": "invalid"})
        )
        self.assertFalse(
            c.is_valid({"type": "external_account", "token_url": "invalid"})
        )

    def test_from_allowed_types(self):
        c = Constraints.from_allowed_types(["service_account", "authorized_user"])
        self.assertTrue(
            c.is_valid(
                {
                    "type": "service_account",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            )
        )
        self.assertTrue(c.is_valid({"type": "authorized_user"}))
        self.assertFalse(
            c.is_valid(
                {
                    "type": "external_account",
                    "token_url": "https://sts.googleapis.com/v1/token",
                }
            )
        )

        with self.assertRaises(ValueError):  # Test no allowed types
            Constraints.from_allowed_types([])

    def test_from_validators(self):

        c = Constraints.from_validators(
            [
                ServiceAccountValidator.from_default("example.com"),
                UserAccountValidator(),
            ]
        )
        self.assertTrue(
            c.is_valid(
                {
                    "type": "service_account",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            )
        )  # Now passes because example.com allows it.
        self.assertTrue(c.is_valid({"type": "authorized_user"}))
        self.assertFalse(c.is_valid({"type": "external_account"}))

        with self.assertRaises(ValueError):  # Test no validators
            Constraints.from_validators(
                []
            )  # Should this raise ValueError? I'm not sure


class ServiceAccountValidatorTest(unittest.TestCase):
    def test_valid(self):
        validator = ServiceAccountValidator.from_default()
        self.assertTrue(
            validator.is_valid(
                {
                    "type": "service_account",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            )
        )

    def test_invalid_token_uri(self):
        validator = ServiceAccountValidator.from_default()
        self.assertFalse(
            validator.is_valid({"type": "service_account", "token_uri": "invalid"})
        )

    def test_missing_token_uri(self):
        validator = ServiceAccountValidator.from_default()
        self.assertFalse(validator.is_valid({"type": "service_account"}))

    def test_custom_token_uri(self):
        validator = ServiceAccountValidator.from_token_uris(
            ["https://custom.com/token"]
        )
        self.assertTrue(
            validator.is_valid(
                {"type": "service_account", "token_uri": "https://custom.com/token"}
            )
        )


class ExternalAccountValidatorTest(unittest.TestCase):
    def test_valid(self):
        validator = ExternalAccountValidator("googleapis.com")
        self.assertTrue(
            validator.is_valid(
                {
                    "type": "external_account",
                    "token_url": "https://sts.googleapis.com/v1/token",
                }
            )
        )

    def test_invalid_domain(self):
        validator = ExternalAccountValidator("example.com")
        self.assertFalse(
            validator.is_valid(
                {
                    "type": "external_account",
                    "token_url": "https://sts.googleapis.com/v1/token",
                }
            )
        )  # Should fail

    def test_missing_token_url(self):
        validator = ExternalAccountValidator()
        self.assertFalse(validator.is_valid({"type": "external_account"}))


if __name__ == "__main__":
    unittest.main()
