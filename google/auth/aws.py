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

"""Helper functions for AWS related operations

This module provides a basic implementation of the `AWS Signature Version 4`_
request signing algorithm.

.. _AWS Signature Version 4: https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
"""

import hashlib
import hmac
import os
from urllib.parse import parse_qs
from urllib.parse import quote
from urllib.parse import urlparse

from google.auth import _helpers

# AWS Signature Version 4 signing algorithm identifier.
_AWS_ALGORITHM = "AWS4-HMAC-SHA256"
# The termination string for the AWS credential scope value as defined in
# https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
_AWS_REQUEST_TYPE = "aws4_request"


class RequestSigner(object):
    """Implements an AWS request signer based on the AWS Signature Version 4 signing
    process.
    https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
    """

    def __init__(self, region_name):
        """Instantiates an AWS request signer used to compute authenticated signed
        requests to AWS APIs based on the AWS Signature Version 4 signing process.

        Args:
            region_name (str): The AWS region to use.
        """

        self._region_name = region_name

    def get_request_options(
        self,
        aws_security_credentials,
        url,
        method,
        request_payload="",
        additional_headers=None,
    ):
        """Generates the signed request for the provided HTTP request for calling
        an AWS API. This follows the steps described at:
        https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

        Args:
            aws_security_credentials (Mapping[str, str]): A dictionary containing
                the AWS security credentials.
            url (str): The AWS service URL containing the canonical URI and
                query string.
            method (str): The HTTP method used to call this API.
            request_payload (Optional[str]): The optional request payload if
                available.
            additional_headers (Optional[Mapping[str, str]]): The optional
                additional headers needed for the requested AWS API.

        Returns:
            Mapping[str, str]: The AWS signed request dictionary object.
        """
        # Get AWS credentials.
        access_key = aws_security_credentials.get("access_key_id")
        secret_key = aws_security_credentials.get("secret_access_key")
        security_token = aws_security_credentials.get("security_token")

        uri = urlparse(url)
        header_map = _generate_authentication_header_map(
            host=uri.hostname,
            canonical_uri=os.path.normpath(uri.path or "/"),
            canonical_querystring=_get_canonical_querystring(uri.query),
            method=method,
            region=self._region_name,
            access_key=access_key,
            secret_key=secret_key,
            security_token=security_token,
            request_payload=request_payload,
            additional_headers=additional_headers,
        )
        headers = {
            "Authorization": header_map.get("authorization_header"),
            "host": uri.hostname,
        }
        # Add x-amz-date if available.
        if "amz_date" in header_map:
            headers["x-amz-date"] = header_map.get("amz_date")
        # Append additional optional headers, eg. X-Amz-Target, Content-Type, etc.
        if additional_headers is not None:
            for key in additional_headers:
                headers[key] = additional_headers[key]

        # Add session token if available.
        if security_token is not None:
            headers["x-amz-security-token"] = security_token

        signed_request = {"url": url, "method": method, "headers": headers}
        if request_payload:
            signed_request["data"] = request_payload
        return signed_request


def _get_canonical_querystring(query):
    """Generates the canonical query string given a raw query string.
    Logic is based on
    https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    Args:
        query (str): The raw query string.

    Returns:
        str: The canonical query string.
    """
    # Parse raw query string.
    querystring = parse_qs(query)
    querystring_encoded_map = {}
    for key in querystring:
        quote_key = quote(key, safe="-_.~")
        # URI encode key.
        querystring_encoded_map[quote_key] = []
        for item in querystring[key]:
            # For each key, URI encode all values for that key.
            querystring_encoded_map[quote_key].append(quote(item, safe="-_.~"))
        # Sort values for each key.
        querystring_encoded_map[quote_key].sort()
    # Sort keys.
    sorted_keys = list(querystring_encoded_map.keys())
    sorted_keys.sort()
    # Reconstruct the query string. Preserve keys with multiple values.
    querystring_encoded_pairs = []
    for key in sorted_keys:
        for item in querystring_encoded_map[key]:
            querystring_encoded_pairs.append("{}={}".format(key, item))
    return "&".join(querystring_encoded_pairs)


def _sign(key, msg):
    """Creates the HMAC-SHA256 hash of the provided message using the provided
    key.

    Args:
        key (str): The HMAC-SHA256 key to use.
        msg (str): The message to hash.

    Returns:
        str: The computed hash bytes.
    """
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _get_signing_key(key, date_stamp, region_name, service_name):
    """Calculates the signing key used to calculate the signature for
    AWS Signature Version 4 based on:
    https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

    Args:
        key (str): The AWS secret access key.
        date_stamp (str): The '%Y%m%d' date format.
        region_name (str): The AWS region.
        service_name (str): The AWS service name, eg. sts.

    Returns:
        str: The signing key bytes.
    """
    k_date = _sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region_name)
    k_service = _sign(k_region, service_name)
    k_signing = _sign(k_service, "aws4_request")
    return k_signing


def _generate_authentication_header_map(
    host,
    canonical_uri,
    canonical_querystring,
    method,
    region,
    access_key,
    secret_key,
    security_token,
    request_payload="",
    additional_headers=None,
):
    """Generates the authentication header map needed for generating the AWS
    Signature Version 4 signed request.

    Args:
        host (str): The AWS service URL hostname.
        canonical_uri (str): The AWS service URL path name.
        canonical_querystring (str): The AWS service URL query string.
        method (str): The HTTP method used to call this API.
        region (str): The AWS region.
        access_key (str): The AWS access key ID.
        secret_key (str): The AWS secret access key.
        security_token (Optional[str]): The AWS security session token. This is
            available for temporary sessions.
        request_payload (Optional[str]): The optional request payload if
            available.
        additional_headers (Optional[Mapping[str, str]]): The optional
            additional headers needed for the requested AWS API.

    Returns:
        Mapping[str, str]: The AWS authentication header dictionary object.
            This contains the x-amz-date and authorization header information.
    """
    # iam.amazonaws.com host => iam service.
    # sts.us-east-2.amazonaws.com host => sts service.
    service_name = host.split(".")[0]

    current_time = _helpers.utcnow()
    amz_date = current_time.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = current_time.strftime("%Y%m%d")

    # Change all additional headers to be lower case.
    full_headers = {}
    if additional_headers is not None:
        for key in additional_headers:
            full_headers[key.lower()] = additional_headers[key]
    # Add AWS session token if available.
    if security_token is not None:
        full_headers["x-amz-security-token"] = security_token

    # Required headers
    full_headers["host"] = host
    # Do not use generated x-amz-date if the date header is provided.
    # Previously the date was not fixed with x-amz- and could be provided
    # manually.
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-header-value-trim.req
    if "date" not in full_headers:
        full_headers["x-amz-date"] = amz_date

    # Header keys need to be sorted alphabetically.
    canonical_headers = ""
    header_keys = list(full_headers.keys())
    header_keys.sort()
    for key in header_keys:
        canonical_headers = "{}{}:{}\n".format(
            canonical_headers, key, full_headers[key]
        )
    signed_headers = ";".join(header_keys)

    payload_hash = hashlib.sha256((request_payload or "").encode("utf-8")).hexdigest()

    # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    canonical_request = "{}\n{}\n{}\n{}\n{}\n{}".format(
        method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash,
    )

    credential_scope = "{}/{}/{}/{}".format(
        date_stamp, region, service_name, _AWS_REQUEST_TYPE
    )

    # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
    string_to_sign = "{}\n{}\n{}\n{}".format(
        _AWS_ALGORITHM,
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    )

    # https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    signing_key = _get_signing_key(secret_key, date_stamp, region, service_name)
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
    authorization_header = "{} Credential={}/{}, SignedHeaders={}, Signature={}".format(
        _AWS_ALGORITHM, access_key, credential_scope, signed_headers, signature
    )

    authentication_header = {"authorization_header": authorization_header}
    # Do not use generated x-amz-date if the date header is provided.
    if "date" not in full_headers:
        authentication_header["amz_date"] = amz_date
    return authentication_header
