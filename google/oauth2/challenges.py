# Copyright 2021 Google LLC
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

""" Challenges for reauthentication.
"""

import abc
import base64
import sys

import six

from google.auth import _helpers
from google.auth import exceptions


REAUTH_ORIGIN = "https://accounts.google.com"


@six.add_metaclass(abc.ABCMeta)
class ReauthChallenge(object):
    """Base class for reauth challenges."""

    @property
    @abc.abstractmethod
    def name(self):  # pragma: NO COVER
        """Returns the name of the challenge."""
        pass

    @property
    @abc.abstractmethod
    def is_locally_eligible(self):  # pragma: NO COVER
        """Returns true if a challenge is supported locally on this machine."""
        pass

    @abc.abstractmethod
    def obtain_challenge_input(self, metadata):  # pragma: NO COVER
        """Performs logic required to obtain credentials and returns it.

        Args:
            metadata: challenge metadata returned in the 'challenges' field in
                the initial reauth request. Includes the 'challengeType' field
                and other challenge-specific fields.

        Returns:
            response that will be send to the reauth service as the content of
            the 'proposalResponse' field in the request body. Usually a dict
            with the keys specific to the challenge. For example,
            {'credential': password} for password challenge.
        """
        pass


class PasswordChallenge(ReauthChallenge):
    """Challenge that asks for user's password."""

    @property
    def name(self):
        return "PASSWORD"

    @property
    def is_locally_eligible(self):
        return True

    def obtain_challenge_input(self, unused_metadata):
        passwd = _helpers.get_user_password("Please enter your password:")
        if not passwd:
            passwd = " "  # avoid the server crashing in case of no password :D
        return {"credential": passwd}


class SecurityKeyChallenge(ReauthChallenge):
    """Challenge that asks for user's security key touch."""

    @property
    def name(self):
        return "SECURITY_KEY"

    @property
    def is_locally_eligible(self):
        return True

    def obtain_challenge_input(self, metadata):
        try:
            import pyu2f.convenience.authenticator
            import pyu2f.errors
            import pyu2f.model
        except ImportError:
            sys.stderr.write(
                "pyu2f is missing. Please install pyu2f to use Security key reauth feature."
            )
            return None
        sk = metadata["securityKey"]
        challenges = sk["challenges"]
        app_id = sk["applicationId"]

        challenge_data = []
        for c in challenges:
            kh = c["keyHandle"].encode("ascii")
            key = pyu2f.model.RegisteredKey(bytearray(base64.urlsafe_b64decode(kh)))
            challenge = c["challenge"].encode("ascii")
            challenge = base64.urlsafe_b64decode(challenge)
            challenge_data.append({"key": key, "challenge": challenge})

        try:
            api = pyu2f.convenience.authenticator.CreateCompositeAuthenticator(
                REAUTH_ORIGIN
            )
            response = api.Authenticate(
                app_id, challenge_data, print_callback=sys.stderr.write
            )
            return {"securityKey": response}
        except pyu2f.errors.U2FError as e:
            if e.code == pyu2f.errors.U2FError.DEVICE_INELIGIBLE:
                sys.stderr.write("Ineligible security key.\n")
            elif e.code == pyu2f.errors.U2FError.TIMEOUT:
                sys.stderr.write("Timed out while waiting for security key touch.\n")
            else:
                raise e
        except pyu2f.errors.NoDeviceFoundError:
            sys.stderr.write("No security key found.\n")
        return None


class SamlChallenge(ReauthChallenge):
    """Challenge that asks the users to browse to their ID Providers."""

    @property
    def name(self):
        return "SAML"

    @property
    def is_locally_eligible(self):
        return True

    def obtain_challenge_input(self, metadata):
        # Magic Arch has not fully supported returning a proper dedirect URL
        # for programmatic SAML users today. So we error our here and request
        # users to complete a web login.
        raise exceptions.ReauthFailError(
            "SAML login is required for the current account to complete reauthentication."
        )


AVAILABLE_CHALLENGES = {
    challenge.name: challenge
    for challenge in [SecurityKeyChallenge(), PasswordChallenge(), SamlChallenge()]
}
