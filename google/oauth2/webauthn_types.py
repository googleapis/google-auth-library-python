# Copyright 2016 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from dataclasses import dataclass
import json
from typing import Any, Dict, List, Optional, Union

from google.auth import exceptions


@dataclass(frozen=True)
class PublicKeyCredentialDescriptor:
    id: str
    transports: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Union[str, List[str]]]:
        cred: Dict[str, Union[str, List[str]]] = {"type": "public-key", "id": self.id}
        if self.transports:
            cred["transports"] = self.transports
        return cred


@dataclass
class AuthenticationExtensionsClientInputs:
    appid: Optional[str] = None

    def to_dict(self) -> Dict[str, str]:
        extensions: Dict[str, str] = {}
        if self.appid:
            extensions["appid"] = self.appid
        return extensions


@dataclass
class GetRequest:
    origin: str
    rpid: str
    challenge: str
    timeout_ms: Optional[int] = None
    allow_credentials: Optional[List[PublicKeyCredentialDescriptor]] = None
    user_verification: Optional[str] = None
    extensions: Optional[AuthenticationExtensionsClientInputs] = None

    def to_json(self) -> str:
        req_options: Dict[str, Any] = {
            "rpid": self.rpid,
            "challenge": self.challenge,
        }
        if self.timeout_ms is not None:
            req_options["timeout"] = self.timeout_ms
        if self.allow_credentials:
            req_options["allowCredentials"] = [
                c.to_dict() for c in self.allow_credentials
            ]
        if self.user_verification:
            req_options["userVerification"] = self.user_verification
        if self.extensions:
            req_options["extensions"] = self.extensions.to_dict()
        return json.dumps(
            {"type": "get", "origin": self.origin, "requestData": req_options}
        )


@dataclass(frozen=True)
class AuthenticatorAssertionResponse:
    client_data_json: str
    authenticator_data: str
    signature: str
    user_handle: Optional[str]


@dataclass(frozen=True)
class GetResponse:
    id: str
    response: AuthenticatorAssertionResponse
    authenticator_attachment: Optional[str]
    client_extension_results: Optional[Dict[str, Any]]

    @staticmethod
    def from_json(json_str: str) -> "GetResponse":
        try:
            resp_json: Dict[str, Any] = json.loads(json_str)
        except ValueError as e:
            raise exceptions.MalformedError("Invalid Get JSON response") from e

        if resp_json.get("type") != "getResponse":
            raise exceptions.MalformedError(
                f"Invalid Get response type: {resp_json.get('type')}"
            )

        pk_cred: Optional[Dict[str, Any]] = resp_json.get("responseData")
        if pk_cred is None:
            if resp_json.get("error"):
                raise exceptions.ReauthFailError(
                    f"WebAuthn.get failure: {resp_json['error']}"
                )
            raise exceptions.MalformedError("Get response is empty")

        if pk_cred.get("type") != "public-key":
            raise exceptions.MalformedError(
                f"Invalid credential type: {pk_cred.get('type')}"
            )

        assertion_json: Dict[str, Any] = pk_cred["response"]
        assertion_resp = AuthenticatorAssertionResponse(
            client_data_json=assertion_json["clientDataJSON"],
            authenticator_data=assertion_json["authenticatorData"],
            signature=assertion_json["signature"],
            user_handle=assertion_json.get("userHandle"),
        )

        return GetResponse(
            id=pk_cred["id"],
            response=assertion_resp,
            authenticator_attachment=pk_cred.get("authenticatorAttachment"),
            client_extension_results=pk_cred.get("clientExtensionResults"),
        )
