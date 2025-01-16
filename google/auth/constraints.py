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

ALLOW_EVERYTHING = "all"

class Constraints(metaclass=ABCMeta):
    # def __init__(
    #     self,
    #     allowEverything = False,
    #     validators = []
    # ):
    #     self._allowEverything = allowEverything
    #     self._validators = validators

    def __init__(self, allow_types=None, universe_domain="googleapis.com"):
       """Initializes Constraints with allowed credential types.

       Args:
           allow_types: Optional[List[str]]: List of allowed credential types. 
                        If None or an empty list, *no* credentials are allowed.
                        To allow all credentials, use ALLOW_EVERYTHING.  Otherwise, 
                        must be a list of valid credential type strings.
                        Supported types: "service_account", "external_account",
                        "authorized_user", "impersonated_service_account", "gdch_service_account".
           universe_domain (str): The universe domain is used for validating in applicabble credential types

       Raises:
           ValueError: If invalid credential types are specified
       """

       all_validators = {
            "service_account": ServiceAccountValidator,
            "external_account": ExternalAccountValidator,
            "authorized_user": UserAccountValidator,
            "impersonated_service_account": ImpersonatedServiceAccountValidator,
            "gdch_service_account": GDCHServiceAccountValidator,
       }    

       self._validators = {}
       if allow_types is None or (isinstance(allow_types, list) and not allow_types): #Treat both None and empty list the same way
           self._allowEverything = False
           return

       elif allow_types == ALLOW_EVERYTHING:
            self._allowEverything = True
            return

       elif isinstance(allow_types, list):  # List of credential types
           self._allowEverything = False

           for credential_type in allow_types:
                validator_class = all_validators.get(credential_type)
                if validator_class is None:
                    raise ValueError(f"Invalid credential type: {credential_type}")

                if credential_type in ("external_account", "impersonated_service_account"):
                    validator = validator_class(universe_domain=universe_domain)
                else:
                    validator = validator_class()
                
                self._validators[credential_type] = validator
           
           return

       else:
           raise ValueError("Invalid allow_types argument, should be None, 'all', or List[str]")


    def isValid(self, json_data):
        if self._allowEverything:
            return True
        
        cred_type = json_data.get("type")
        if cred_type not in self._validators:
            return False
        
        return self._validators[cred_type].is_valid(json_data)
    

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

    def get_type(self):
        return "service_account"
    

class ExternalAccountValidator(Validator):
    """Validator for external account credentials."""

    def __init__(
            self,
            universe_domain="googleapis.com"):
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

    def __init__(
            self,
            universe_domain="googleapis.com"):
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
                return None # Handle cases where there's no slash

            print(f"\ntruncated url={url[:last_slash_index+1]}\n")
            return url[:last_slash_index+1]

        except ValueError as e:  # Handle any parsing errors
            print(f"Invalid URL: {e}")
            raise ValueError(f"Invalid URL: {e}")
    

class GDCHServiceAccountValidator(Validator):
    """Validator for GDCH service account credentials"""
    def get_type(self):
        return "gdch_service_account"
    
