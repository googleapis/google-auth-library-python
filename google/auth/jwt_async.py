# Copyright 2020 Google LLC
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

"""JSON Web Tokens

Provides support for creating (encoding) and verifying (decoding) JWTs,
especially JWTs generated and consumed by Google infrastructure.

See `rfc7519`_ for more details on JWTs.

To encode a JWT use :func:`encode`::

    from google.auth import crypt
    from google.auth import jwt

    signer = crypt.Signer(private_key)
    payload = {'some': 'payload'}
    encoded = jwt.encode(signer, payload)

To decode a JWT and verify claims use :func:`decode`::

    claims = jwt.decode(encoded, certs=public_certs)

You can also skip verification::

    claims = jwt.decode(encoded, verify=False)

.. _rfc7519: https://tools.ietf.org/html/rfc7519

"""

try:
    from collections.abc import Mapping
# Python 2.7 compatibility
except ImportError:  # pragma: NO COVER
    from collections import Mapping

import json

import six

import google.auth
from google.auth import _helpers
from google.auth import crypt
from google.auth import jwt

try:
    from google.auth.crypt import es256
except ImportError:  # pragma: NO COVER
    es256 = None

_DEFAULT_TOKEN_LIFETIME_SECS = 3600  # 1 hour in seconds
_DEFAULT_MAX_CACHE_SIZE = 10
_ALGORITHM_TO_VERIFIER_CLASS = {"RS256": crypt.RSAVerifier}
_CRYPTOGRAPHY_BASED_ALGORITHMS = frozenset(["ES256"])

if es256 is not None:  # pragma: NO COVER
    _ALGORITHM_TO_VERIFIER_CLASS["ES256"] = es256.ES256Verifier


def encode(signer, payload, header=None, key_id=None):
    """Make a signed JWT.

    Args:
        signer (google.auth.crypt.Signer): The signer used to sign the JWT.
        payload (Mapping[str, str]): The JWT payload.
        header (Mapping[str, str]): Additional JWT header payload.
        key_id (str): The key id to add to the JWT header. If the
            signer has a key id it will be used as the default. If this is
            specified it will override the signer's key id.

    Returns:
        bytes: The encoded JWT.
    """
    if header is None:
        header = {}

    if key_id is None:
        key_id = signer.key_id

    header.update({"typ": "JWT"})

    if es256 is not None and isinstance(signer, es256.ES256Signer):
        header.update({"alg": "ES256"})
    else:
        header.update({"alg": "RS256"})

    if key_id is not None:
        header["kid"] = key_id

    segments = [
        _helpers.unpadded_urlsafe_b64encode(json.dumps(header).encode("utf-8")),
        _helpers.unpadded_urlsafe_b64encode(json.dumps(payload).encode("utf-8")),
    ]

    signing_input = b".".join(segments)
    signature = signer.sign(signing_input)
    segments.append(_helpers.unpadded_urlsafe_b64encode(signature))

    return b".".join(segments)


def _decode_jwt_segment(encoded_section):
    """Decodes a single JWT segment."""
    section_bytes = _helpers.padded_urlsafe_b64decode(encoded_section)
    try:
        return json.loads(section_bytes.decode("utf-8"))
    except ValueError as caught_exc:
        new_exc = ValueError("Can't parse segment: {0}".format(section_bytes))
        six.raise_from(new_exc, caught_exc)


def _unverified_decode(token):
    """Decodes a token and does no verification.

    Args:
        token (Union[str, bytes]): The encoded JWT.

    Returns:
        Tuple[str, str, str, str]: header, payload, signed_section, and
            signature.

    Raises:
        ValueError: if there are an incorrect amount of segments in the token.
    """
    token = _helpers.to_bytes(token)

    if token.count(b".") != 2:
        raise ValueError("Wrong number of segments in token: {0}".format(token))

    encoded_header, encoded_payload, signature = token.split(b".")
    signed_section = encoded_header + b"." + encoded_payload
    signature = _helpers.padded_urlsafe_b64decode(signature)

    # Parse segments
    header = _decode_jwt_segment(encoded_header)
    payload = _decode_jwt_segment(encoded_payload)

    return header, payload, signed_section, signature


def decode_header(token):
    """Return the decoded header of a token.

    No verification is done. This is useful to extract the key id from
    the header in order to acquire the appropriate certificate to verify
    the token.

    Args:
        token (Union[str, bytes]): the encoded JWT.

    Returns:
        Mapping: The decoded JWT header.
    """
    header, _, _, _ = _unverified_decode(token)
    return header


def _verify_iat_and_exp(payload):
    """Verifies the ``iat`` (Issued At) and ``exp`` (Expires) claims in a token
    payload.

    Args:
        payload (Mapping[str, str]): The JWT payload.

    Raises:
        ValueError: if any checks failed.
    """
    now = _helpers.datetime_to_secs(_helpers.utcnow())

    # Make sure the iat and exp claims are present.
    for key in ("iat", "exp"):
        if key not in payload:
            raise ValueError("Token does not contain required claim {}".format(key))

    # Make sure the token wasn't issued in the future.
    iat = payload["iat"]
    # Err on the side of accepting a token that is slightly early to account
    # for clock skew.
    earliest = iat - _helpers.CLOCK_SKEW_SECS
    if now < earliest:
        raise ValueError("Token used too early, {} < {}".format(now, iat))

    # Make sure the token wasn't issued in the past.
    exp = payload["exp"]
    # Err on the side of accepting a token that is slightly out of date
    # to account for clow skew.
    latest = exp + _helpers.CLOCK_SKEW_SECS
    if latest < now:
        raise ValueError("Token expired, {} < {}".format(latest, now))


def decode(token, certs=None, verify=True, audience=None):
    """Decode and verify a JWT.

    Args:
        token (str): The encoded JWT.
        certs (Union[str, bytes, Mapping[str, Union[str, bytes]]]): The
            certificate used to validate the JWT signature. If bytes or string,
            it must the the public key certificate in PEM format. If a mapping,
            it must be a mapping of key IDs to public key certificates in PEM
            format. The mapping must contain the same key ID that's specified
            in the token's header.
        verify (bool): Whether to perform signature and claim validation.
            Verification is done by default.
        audience (str): The audience claim, 'aud', that this JWT should
            contain. If None then the JWT's 'aud' parameter is not verified.

    Returns:
        Mapping[str, str]: The deserialized JSON payload in the JWT.

    Raises:
        ValueError: if any verification checks failed.
    """
    header, payload, signed_section, signature = _unverified_decode(token)

    if not verify:
        return payload

    # Pluck the key id and algorithm from the header and make sure we have
    # a verifier that can support it.
    key_alg = header.get("alg")
    key_id = header.get("kid")

    try:
        verifier_cls = _ALGORITHM_TO_VERIFIER_CLASS[key_alg]
    except KeyError as exc:
        if key_alg in _CRYPTOGRAPHY_BASED_ALGORITHMS:
            six.raise_from(
                ValueError(
                    "The key algorithm {} requires the cryptography package "
                    "to be installed.".format(key_alg)
                ),
                exc,
            )
        else:
            six.raise_from(
                ValueError("Unsupported signature algorithm {}".format(key_alg)), exc
            )

    # If certs is specified as a dictionary of key IDs to certificates, then
    # use the certificate identified by the key ID in the token header.
    if isinstance(certs, Mapping):
        if key_id:
            if key_id not in certs:
                raise ValueError("Certificate for key id {} not found.".format(key_id))
            certs_to_check = [certs[key_id]]
        # If there's no key id in the header, check against all of the certs.
        else:
            certs_to_check = certs.values()
    else:
        certs_to_check = certs

    # Verify that the signature matches the message.
    if not crypt.verify_signature(
        signed_section, signature, certs_to_check, verifier_cls
    ):
        raise ValueError("Could not verify token signature.")

    # Verify the issued at and created times in the payload.
    _verify_iat_and_exp(payload)

    # Check audience.
    if audience is not None:
        claim_audience = payload.get("aud")
        if audience != claim_audience:
            raise ValueError(
                "Token has wrong audience {}, expected {}".format(
                    claim_audience, audience
                )
            )

    return payload


class Credentials(
    jwt.Credentials,
    google.auth.credentials_async.Signing,
    google.auth.credentials_async.Credentials,
):
    """Credentials that use a JWT as the bearer token.

    These credentials require an "audience" claim. This claim identifies the
    intended recipient of the bearer token.

    The constructor arguments determine the claims for the JWT that is
    sent with requests. Usually, you'll construct these credentials with
    one of the helper constructors as shown in the next section.

    To create JWT credentials using a Google service account private key
    JSON file::

        audience = 'https://pubsub.googleapis.com/google.pubsub.v1.Publisher'
        credentials = jwt_async.Credentials.from_service_account_file(
            'service-account.json',
            audience=audience)

    If you already have the service account file loaded and parsed::

        service_account_info = json.load(open('service_account.json'))
        credentials = jwt_async.Credentials.from_service_account_info(
            service_account_info,
            audience=audience)

    Both helper methods pass on arguments to the constructor, so you can
    specify the JWT claims::

        credentials = jwt_async.Credentials.from_service_account_file(
            'service-account.json',
            audience=audience,
            additional_claims={'meta': 'data'})

    You can also construct the credentials directly if you have a
    :class:`~google.auth.crypt.Signer` instance::

        credentials = jwt_async.Credentials(
            signer,
            issuer='your-issuer',
            subject='your-subject',
            audience=audience)

    The claims are considered immutable. If you want to modify the claims,
    you can easily create another instance using :meth:`with_claims`::

        new_audience = (
            'https://pubsub.googleapis.com/google.pubsub.v1.Subscriber')
        new_credentials = credentials.with_claims(audience=new_audience)
    """


class OnDemandCredentials(
    jwt.OnDemandCredentials,
    google.auth.credentials_async.Signing,
    google.auth.credentials_async.Credentials,
):
    """On-demand JWT credentials.

    Like :class:`Credentials`, this class uses a JWT as the bearer token for
    authentication. However, this class does not require the audience at
    construction time. Instead, it will generate a new token on-demand for
    each request using the request URI as the audience. It caches tokens
    so that multiple requests to the same URI do not incur the overhead
    of generating a new token every time.

    This behavior is especially useful for `gRPC`_ clients. A gRPC service may
    have multiple audience and gRPC clients may not know all of the audiences
    required for accessing a particular service. With these credentials,
    no knowledge of the audiences is required ahead of time.

    .. _grpc: http://www.grpc.io/
    """
