# Copyright 2015 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from abc import ABCMeta, abstractmethod
import urllib.parse

from enum import Enum

AUTHORIZED_USER = "authorized_user"
SERVICE_ACCOUNT = "service_account"
EXTERNAL_ACCOUNT = "external_account"
EXTERNAL_ACCOUNT_AUTHORIZED_USER = "external_account_authorized_user"
IMPERSONATED_SERVICE_ACCOUNT = "impersonated_service_account"
GDCH_SERVICE_ACCOUNT = "gdch_service_account"


class CredentialConstraintsChoice(Enum):
    ALLOW_EVERYTHING_INSECURE = 1
    USE_VALIDATORS = 2


class Constraints(metaclass=ABCMeta):
    def __init__(self, constraints_choice, validators=None):
        self._constraints_choice = constraints_choice
        self._validators = validators or {}

    @classmethod
    def allow_everything_insecure(cls):
        return cls(
            constraints_choice=CredentialConstraintsChoice.ALLOW_EVERYTHING_INSECURE
        )

    @classmethod
    def allow_everything_secure(cls, universe_domain="googleapis.com"):
        return cls(
            constraints_choice=CredentialConstraintsChoice.USE_VALIDATORS,
            validators=cls._build_default_validators(universe_domain),
        )

    @classmethod
    def from_allowed_types(cls, allow_types, universe_domain="googleapis.com"):
        """Allows only the specified credential types using default validators."""
        if not allow_types:
            raise ValueError("Provide atleas one allowed type")

        validators = cls._build_validators_from_types(allow_types, universe_domain)
        return cls(
            constraints_choice=CredentialConstraintsChoice.USE_VALIDATORS,
            validators=validators,
        )

    @classmethod
    def from_validators(cls, validators):
        """Allows credentials validated by the provided custom validators."""

        validators_dict = {v.get_type(): v for v in validators}
        return cls(
            constraints_choice=CredentialConstraintsChoice.USE_VALIDATORS,
            validators=validators_dict,
        )

    @staticmethod
    def _build_default_validators(universe_domain):
        """Builds default validators for known secure types."""

        return {
            "service_account": ServiceAccountValidator.from_default(universe_domain),
            "external_account": ExternalAccountValidator(universe_domain),
            "authorized_user": UserAccountValidator(),
            "impersonated_service_account": ImpersonatedServiceAccountValidator(
                universe_domain
            ),
            "gdch_service_account": GDCHServiceAccountValidator(),
        }

    @staticmethod
    def _build_validators_from_types(allow_types, universe_domain):

        all_validators = {
            "service_account": ServiceAccountValidator,
            "external_account": ExternalAccountValidator,
            "authorized_user": UserAccountValidator,
            "impersonated_service_account": ImpersonatedServiceAccountValidator,
            "gdch_service_account": GDCHServiceAccountValidator,
        }

        validators = {}

        if allow_types:  # Check if allow_types is not empty
            for credential_type in allow_types:
                validator_class = all_validators.get(credential_type)
                if not validator_class:
                    raise ValueError(f"Invalid credential type: {credential_type}")

                if credential_type in (
                    "external_account",
                    "impersonated_service_account",
                ):
                    validator = validator_class(universe_domain=universe_domain)
                elif credential_type == SERVICE_ACCOUNT:
                    validator = validator_class.from_default(universe_domain)
                else:
                    validator = validator_class()

                validators[credential_type] = validator
        return validators

    def is_valid(self, json_data):
        if (
            self._constraints_choice
            == CredentialConstraintsChoice.ALLOW_EVERYTHING_INSECURE
        ):
            return True

        credential_type = json_data.get("type")

        validator = self._validators.get(credential_type)

        return validator and validator.is_valid(json_data)


class Validator(metaclass=ABCMeta):
    """Base class for validating JSON data against specific criteria."""

    @abstractmethod
    def get_type(self):
        """Returns the type of validator."""
        raise NotImplementedError()

    def is_valid(self, json_data):
        """
        Checks if the given JSON data is valid.

        Args:
            json_data (dict): The JSON data to validate.

        Returns:
            bool: True if the JSON data is valid, False otherwise.
        """
        return json_data.get("type") == self.get_type()


class ServiceAccountValidator(Validator):
    """Validator for service account credentials."""

    ALLOWED_TOKEN_URIS = [
        "https://oauth2.googleapis.com/token",
        "https://oauth2.mtlsgoogleapis.com/token",
        "https://accounts.google.com/o/oauth2/token",
    ]
    # TODO: Add PSC

    def __init__(self, allowed_token_uris, universe_domain):
        self._universe_domain = universe_domain
        self._allowed_token_uris = allowed_token_uris

    @classmethod
    def from_default(cls, universe_domain="googleapis.com"):
        return cls(cls.ALLOWED_TOKEN_URIS, universe_domain)

    @classmethod
    def from_token_uris(cls, token_uris, universe_domain="googleapis.com"):
        return cls(token_uris, universe_domain)

    def get_type(self):
        return "service_account"

    def is_valid(self, json_data):
        actual_token_uri = json_data.get("token_uri")
        actual_universe_domain = json_data.get("universe_domain")
        return actual_token_uri in self._allowed_token_uris and (
            actual_universe_domain is None
            or actual_universe_domain == self._universe_domain
        )


# TODO: All other validators are WIP
class ExternalAccountValidator(Validator):
    """Validator for external account credentials."""

    def __init__(self, universe_domain="googleapis.com"):
        self._universe_domain = universe_domain

    def get_type(self):
        return "external_account"

    def is_valid(self, json_data):
        actual_token_url = json_data.get("token_url")
        expected_token_url = f"https://sts.{self._universe_domain}/v1/token"

        return actual_token_url == expected_token_url


class UserAccountValidator(Validator):
    """Validator for user account credentials."""

    def get_type(self):
        return "authorized_user"


class ImpersonatedServiceAccountValidator(Validator):
    """Validator for impersonated service account credentials"""

    def __init__(self, universe_domain="googleapis.com"):
        self._universe_domain = universe_domain

    def get_type(self):
        return "impersonated_service_account"

    def is_valid(self, json_data):
        iam_url = json_data.get("service_account_impersonation_url")
        # actual_url = self.extract_iam_url(
        #     json_data.get("service_account_impersonation_url"))
        expected_url = f"https://iamcredentials.{self._universe_domain}/v1/projects/-/serviceAccounts/"

        return iam_url.startswith(expected_url)

    def extract_iam_url(self, url):
        """
        Extracts the service account path (up to the last slash) from a generateAccessToken URL.

        Args:
            url: The generateAccessToken URL.

        Returns:
            str: The service account path, or None if the URL is invalid.
            
        """
        try:
            parsed_url = urllib.parse.urlparse(url)

            path = parsed_url.path
            last_slash_index = path.rfind("/")
            print(f"\nlast_slash_index={last_slash_index}\n")

            if last_slash_index == -1:
                return None  # Handle cases where there's no slash

            print(f"\ntruncated url={url[:last_slash_index+1]}\n")
            return url[: last_slash_index + 1]

        except ValueError as e:  # Handle any parsing errors
            print(f"Invalid URL: {e}")
            raise ValueError(f"Invalid URL: {e}")


class GDCHServiceAccountValidator(Validator):
    """Validator for GDCH service account credentials"""

    def get_type(self):
        return "gdch_service_account"


ALLOW_EVERYTHING = "all"


# class Constraints(metaclass=ABCMeta):
#     # def __init__(
#     #     self,
#     #     allowEverything = False,
#     #     validators = []
#     # ):
#     #     self._allowEverything = allowEverything
#     #     self._validators = validators

#     def __init__(self, allow_everything, validators=None):
#         self._validators = validators
#         if self._validators is None:
#             self._validators = {}

#         self._allowEverything = allow_everything

#     def fromCredentialTypeStrings(
#         cls, constraint_choise, allow_types=None, universe_domain="googleapis.com"
#     ):
#         """Initializes Constraints with allowed credential types.

#        Args:
#            allow_types: Optional[List[str]]: List of allowed credential types.
#                         If None or an empty list, *no* credentials are allowed.
#                         To allow all credentials, use ALLOW_EVERYTHING.  Otherwise,
#                         must be a list of valid credential type strings.
#                         Supported types: "service_account", "external_account",
#                         "authorized_user", "impersonated_service_account", "gdch_service_account".
#            universe_domain (str): The universe domain is used for validating in applicabble credential types

#        Raises:
#            ValueError: If invalid credential types are specified
#        """

#         if allow_types is None or (
#             isinstance(allow_types, list) and not allow_types
#         ):  # Treat both None and empty list the same way
#             return cls(allow_everything=False)

#         elif allow_types == ALLOW_EVERYTHING:
#             return cls(allow_everything=True)

#         elif isinstance(allow_types, list):  # List of credential types
#             all_validators = {
#                 "service_account": ServiceAccountValidator,
#                 "external_account": ExternalAccountValidator,
#                 "authorized_user": UserAccountValidator,
#                 "impersonated_service_account": ImpersonatedServiceAccountValidator,
#                 "gdch_service_account": GDCHServiceAccountValidator,
#             }

#             validators = {}

#             for credential_type in allow_types:
#                 validator_class = all_validators.get(credential_type)
#                 if validator_class is None:
#                     raise ValueError(f"Invalid credential type: {credential_type}")

#                 if credential_type in (
#                     "external_account",
#                     "impersonated_service_account",
#                 ):
#                     validator = validator_class(universe_domain=universe_domain)
#                 else:
#                     validator = validator_class()

#                 validators[credential_type] = validator

#             return cls(allow_everything=False, validators=validators)

#         else:
#             raise ValueError(
#                 "Invalid allow_types argument, should be None, 'all', or List[str]"
#             )

#     def fromValidators(cls, validators):
#         validator_dict = {}

#         for validator in validators:
#             validator_dict[validator.get_type()] = validator

#         return cls(allow_everything=False, validators=validator_dict)

#     def isValid(self, json_data):
#         if self._allowEverything:
#             return True

#         cred_type = json_data.get("type")
#         if cred_type not in self._validators:
#             return False

#         return self._validators[cred_type].is_valid(json_data)
