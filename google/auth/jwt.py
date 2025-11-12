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

from __future__ import annotations

from typing import Any, Mapping, Optional, Union, Tuple, cast, List, Type

try:
    from collections.abc import Mapping as CollectionsMapping
except ImportError:
    from typing import Mapping as CollectionsMapping

import copy
import datetime
import json
import urllib.parse

import cachetools

from google.auth import _helpers
from google.auth import _service_account_info
from google.auth import crypt
from google.auth import exceptions
import google.auth.credentials

try:
    from google.auth.crypt import es256
except ImportError:  # pragma: NO COVER
    es256 = None  # type: ignore

_DEFAULT_TOKEN_LIFETIME_SECS: int = 3600
_DEFAULT_MAX_CACHE_SIZE: int = 10

_ALGORITHM_TO_VERIFIER_CLASS: dict[str, Type[crypt.Verifier]] = {"RS256": crypt.RSAVerifier}
_CRYPTOGRAPHY_BASED_ALGORITHMS: frozenset[str] = frozenset(["ES256"])

if es256 is not None:  # pragma: NO COVER
    _ALGORITHM_TO_VERIFIER_CLASS["ES256"] = es256.ES256Verifier


def encode(
    signer: crypt.Signer,
    payload: Mapping[str, Any],
    header: Optional[Mapping[str, Any]] = None,
    key_id: Optional[str] = None,
) -> bytes:
    if header is None:
        header = {}

    if key_id is None:
        key_id = signer.key_id

    header = dict(header)
    header.update({"typ": "JWT"})

    if "alg" not in header:
        if es256 is not None and isinstance(signer, es256.ES256Signer):
            header.update({"alg": "ES256"})
        else:
            header.update({"alg": "RS256"})

    if key_id is not None:
        header["kid"] = key_id

    segments = [
        _helpers.unpadded_urlsafe_b64encode(json.dumps(header).encode("utf-8")),  # type: ignore
        _helpers.unpadded_urlsafe_b64encode(json.dumps(payload).encode("utf-8")),  # type: ignore
    ]

    signing_input = b".".join(segments)
    signature = signer.sign(signing_input)  # type: ignore
    segments.append(_helpers.unpadded_urlsafe_b64encode(signature))  # type: ignore

    return b".".join(segments)


def _decode_jwt_segment(encoded_section: bytes) -> Any:
    section_bytes = _helpers.padded_urlsafe_b64decode(encoded_section)  # type: ignore
    try:
        return json.loads(section_bytes.decode("utf-8"))
    except ValueError as caught_exc:
        decoded_segment: str = encoded_section.decode("utf-8", errors="replace")
        msg: str = "Can't parse segment: {}".format(decoded_segment)
        raise exceptions.MalformedError(msg) from caught_exc  # type: ignore


def _unverified_decode(
    token: Union[str, bytes]
) -> Tuple[Mapping[str, Any], Mapping[str, Any], bytes, bytes]:
    token = _helpers.to_bytes(token)  # type: ignore
    assert isinstance(token, bytes)

    if token.count(b".") != 2:
        decoded_token = token.decode("utf-8", errors="replace")
        msg = "Wrong number of segments in token: {}".format(decoded_token)
        raise exceptions.MalformedError(msg)  # type: ignore

        
    encoded_header, encoded_payload, signature = token.split(b".")
    signed_section = encoded_header + b"." + encoded_payload
    signature = _helpers.padded_urlsafe_b64decode(signature)  # type: ignore

    header = _decode_jwt_segment(encoded_header)
    payload = _decode_jwt_segment(encoded_payload)

    if not isinstance(header, CollectionsMapping):
        raise exceptions.MalformedError("Header segment should be a JSON object.")  # type: ignore

    if not isinstance(payload, CollectionsMapping):
        raise exceptions.MalformedError("Payload segment should be a JSON object.")  # type: ignore

    return cast(Mapping[str, Any], header), cast(Mapping[str, Any], payload), signed_section, signature


def decode_header(token: Union[str, bytes]) -> Mapping[str, Any]:
    header, _, _, _ = _unverified_decode(token)
    return header


def _verify_iat_and_exp(payload: Mapping[str, Any], clock_skew_in_seconds: int = 0) -> None:
    now = _helpers.datetime_to_secs(_helpers.utcnow())  # type: ignore

    for key in ("iat", "exp"):
        if key not in payload:
            raise exceptions.MalformedError(  # type: ignore
                f"Token does not contain required claim {key}"
            )

    iat = payload["iat"]
    earliest = iat - clock_skew_in_seconds
    if now < earliest:
        raise exceptions.InvalidValue(  # type: ignore
            f"Token used too early, {now} < {iat}. Check that your clock is correct."
        )

    exp = payload["exp"]
    latest = exp + clock_skew_in_seconds
    if latest < now:
        raise exceptions.InvalidValue(f"Token expired, {latest} < {now}")  # type: ignore


def decode(
    token: Union[str, bytes],
    certs: Union[str, bytes, Mapping[str, Union[str, bytes]], None] = None,
    verify: bool = True,
    audience: Union[str, List[str], None] = None,
    clock_skew_in_seconds: int = 0,
) -> Mapping[str, Any]:
    header, payload, signed_section, signature = _unverified_decode(token)

    if not verify:
        return payload

    key_alg = header.get("alg")
    key_id = header.get("kid")

    try:
        verifier_cls = _ALGORITHM_TO_VERIFIER_CLASS[key_alg]  # type: ignore
    except KeyError as exc:
        raise exceptions.InvalidValue(f"Unsupported algorithm: {key_alg}") from exc  # type: ignore

    if isinstance(certs, CollectionsMapping):
        if key_id:
            if key_id not in certs:
                raise exceptions.MalformedError(f"Certificate for key id {key_id} not found.")  # type: ignore
            certs_to_check = [certs[key_id]]
        else:
            certs_to_check = list(certs.values())
    else:
        certs_to_check = certs  # type: ignore

    if not crypt.verify_signature(signed_section, signature, certs_to_check, verifier_cls):  # type: ignore
        raise exceptions.MalformedError("Could not verify token signature.")  # type: ignore

    _verify_iat_and_exp(payload, clock_skew_in_seconds)

    if audience is not None:
        claim_audience = payload.get("aud")
        if isinstance(audience, str):
            audience = [audience]
        if claim_audience not in audience:
            raise exceptions.InvalidValue(  # type: ignore
                f"Token has wrong audience {claim_audience}, expected one of {audience}"
            )

    return payload


class Credentials(
    google.auth.credentials.Signing,
    google.auth.credentials.CredentialsWithQuotaProject,
):
    def __init__(
        self,
        signer: crypt.Signer,
        issuer: str,
        subject: str,
        audience: str,
        additional_claims: Optional[Mapping[str, str]] = None,
        token_lifetime: int = _DEFAULT_TOKEN_LIFETIME_SECS,
        quota_project_id: Optional[str] = None,
    ) -> None:
        super().__init__()  # type: ignore
        self._signer = signer
        self._issuer = issuer
        self._subject = subject
        self._audience = audience
        self._token_lifetime = token_lifetime
        self._quota_project_id = quota_project_id
        self._additional_claims = dict(additional_claims) if additional_claims else {}

    @classmethod
    def _from_signer_and_info(
        cls,
        signer: crypt.Signer,
        info: Mapping[str, str],
        **kwargs: Any,
    ) -> Credentials:
        kwargs.setdefault("subject", info["client_email"])
        kwargs.setdefault("issuer", info["client_email"])
        return cls(signer, **kwargs)

    @classmethod
    def from_service_account_info(
        cls, info: Mapping[str, str], **kwargs: Any
    ) -> Credentials:
        signer = _service_account_info.from_dict(info, require=["client_email"])  # type: ignore
        return cls._from_signer_and_info(signer, info, **kwargs)

    @classmethod
    def from_service_account_file(
        cls, filename: str, **kwargs: Any
    ) -> Credentials:
        info, signer = _service_account_info.from_filename(  # type: ignore
            filename, require=["client_email"]
        )
        return cls._from_signer_and_info(signer, info, **kwargs)

    @classmethod
    def from_signing_credentials(
        cls, credentials: google.auth.credentials.Signing, audience: str, **kwargs: Any
    ) -> Credentials:
        kwargs.setdefault("issuer", credentials.signer_email)
        kwargs.setdefault("subject", credentials.signer_email)
        return cls(credentials.signer, audience=audience, **kwargs)

    def with_claims(
        self,
        issuer: Optional[str] = None,
        subject: Optional[str] = None,
        additional_claims: Optional[Mapping[str, str]] = None,
    ) -> Credentials:
        new_additional_claims = copy.deepcopy(self._additional_claims)
        new_additional_claims.update(additional_claims or {})

        return self.__class__(
            self._signer,
            issuer=issuer or self._issuer,
            subject=subject or self._subject,
            audience=self._audience,
            additional_claims=new_additional_claims,
            quota_project_id=self._quota_project_id,
        )

    def with_quota_project(self, quota_project_id: str) -> Credentials:
        return self.__class__(
            self._signer,
            issuer=self._issuer,
            subject=self._subject,
            audience=self._audience,
            additional_claims=self._additional_claims,
            quota_project_id=quota_project_id,
        )

    def _make_jwt(self) -> Tuple[bytes, datetime.datetime]:
        now = _helpers.utcnow()  # type: ignore
        expiry = now + datetime.timedelta(seconds=self._token_lifetime)

        payload: dict[str, Any] = {
            "iss": self._issuer,
            "sub": self._subject,
            "iat": _helpers.datetime_to_secs(now),  # type: ignore
            "exp": _helpers.datetime_to_secs(expiry),  # type: ignore
        }
        if self._audience:
            payload["aud"] = self._audience

        payload.update(self._additional_claims)
        jwt = encode(self._signer, payload)
        return jwt, expiry

    def refresh(self, request: Any) -> None:
        self.token, self.expiry = self._make_jwt()

    def sign_bytes(self, message: bytes) -> bytes:
        return self._signer.sign(message)  # type: ignore

    @property
    def signer_email(self) -> str:
        return self._issuer

    @property
    def signer(self) -> crypt.Signer:
        return self._signer

    @property
    def additional_claims(self) -> Mapping[str, str]:
        return self._additional_claims
