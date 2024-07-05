# Copyright 2016 Google LLC
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

"""Transport adapter for Base Requests."""

import os

import abc

try:
    import requests
except ImportError as caught_exc:  # pragma: NO COVER
    raise ImportError(
        "The requests library is not installed from please install the requests package to use the requests transport."
    ) from caught_exc
import requests.adapters  # pylint: disable=ungrouped-imports
import requests.exceptions  # pylint: disable=ungrouped-imports
from requests.packages.urllib3.util.ssl_ import (  # type: ignore
    create_urllib3_context,
) # pylint: disable=ungrouped-imports
from google.auth import transport
from google.auth import environment_vars
from google.auth import exceptions
import google.auth.transport._mtls_helper


_DEFAULT_TIMEOUT = 120  # in second


class _MutualTlsAdapter(requests.adapters.HTTPAdapter):
    """
    A TransportAdapter that enables mutual TLS.

    Args:
        cert (bytes): client certificate in PEM format
        key (bytes): client private key in PEM format

    Raises:
        ImportError: if certifi or pyOpenSSL is not installed
        OpenSSL.crypto.Error: if client cert or key is invalid
    """

    def __init__(self, cert, key):
        import certifi
        from OpenSSL import crypto
        import urllib3.contrib.pyopenssl  # type: ignore

        urllib3.contrib.pyopenssl.inject_into_urllib3()

        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

        ctx_poolmanager = create_urllib3_context()
        ctx_poolmanager.load_verify_locations(cafile=certifi.where())
        ctx_poolmanager._ctx.use_certificate(x509)
        ctx_poolmanager._ctx.use_privatekey(pkey)
        self._ctx_poolmanager = ctx_poolmanager

        ctx_proxymanager = create_urllib3_context()
        ctx_proxymanager.load_verify_locations(cafile=certifi.where())
        ctx_proxymanager._ctx.use_certificate(x509)
        ctx_proxymanager._ctx.use_privatekey(pkey)
        self._ctx_proxymanager = ctx_proxymanager

        super(_MutualTlsAdapter, self).__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx_poolmanager
        super(_MutualTlsAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx_proxymanager
        return super(_MutualTlsAdapter, self).proxy_manager_for(*args, **kwargs)


class _MutualTlsOffloadAdapter(requests.adapters.HTTPAdapter):
    """
    A TransportAdapter that enables mutual TLS and offloads the client side
    signing operation to the signing library.

    Args:
        enterprise_cert_file_path (str): the path to a enterprise cert JSON
            file. The file should contain the following field:

                {
                    "libs": {
                        "signer_library": "...",
                        "offload_library": "..."
                    }
                }

    Raises:
        ImportError: if certifi or pyOpenSSL is not installed
        google.auth.exceptions.MutualTLSChannelError: If mutual TLS channel
            creation failed for any reason.
    """

    def __init__(self, enterprise_cert_file_path):
        import certifi
        from google.auth.transport import _custom_tls_signer

        self.signer = _custom_tls_signer.CustomTlsSigner(enterprise_cert_file_path)
        self.signer.load_libraries()

        if not self.signer.should_use_provider():
            import urllib3.contrib.pyopenssl

            urllib3.contrib.pyopenssl.inject_into_urllib3()

        poolmanager = create_urllib3_context()
        poolmanager.load_verify_locations(cafile=certifi.where())
        self.signer.attach_to_ssl_context(poolmanager)
        self._ctx_poolmanager = poolmanager

        proxymanager = create_urllib3_context()
        proxymanager.load_verify_locations(cafile=certifi.where())
        self.signer.attach_to_ssl_context(proxymanager)
        self._ctx_proxymanager = proxymanager

        super(_MutualTlsOffloadAdapter, self).__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx_poolmanager
        super(_MutualTlsOffloadAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx_proxymanager
        return super(_MutualTlsOffloadAdapter, self).proxy_manager_for(*args, **kwargs)


class _BaseAuthorizedSession(metaclass=abc.ABCMeta):
    """Base class for a Request Session with credentials. This class is intended to capture
    the common logic between synchronous and asynchronous request sessions and is not intended to
    be instantiated directly.

    Args:
        credentials (google.auth._credentials_base.BaseCredentials): The credentials to
            add to the request.
        refresh_status_codes (Sequence[int]): Which HTTP status codes indicate
            that credentials should be refreshed and the request should be
            retried.
        max_refresh_attempts (int): The maximum number of times to attempt to
            refresh the credentials and retry the request.
        refresh_timeout (Optional[int]): The timeout value in seconds for
            credential refresh HTTP requests.
        auth_request (google.auth.transport.requests.Request):
            (Optional) An instance of
            :class:`~google.auth.transport.requests.Request` used when
            refreshing credentials. If not passed,
            an instance of :class:`~google.auth.transport.requests.Request`
            is created.
        default_host (Optional[str]): A host like "pubsub.googleapis.com".
            This is used when a self-signed JWT is created from service
            account credentials.
    """


    def __init__(
        self,
        credentials,
        refresh_status_codes=transport.DEFAULT_REFRESH_STATUS_CODES,
        max_refresh_attempts=transport.DEFAULT_MAX_REFRESH_ATTEMPTS,
        refresh_timeout=None,
        auth_request=None,
        default_host=None,
    ):
        self.credentials = credentials
        self._refresh_status_codes = refresh_status_codes
        self._max_refresh_attempts = max_refresh_attempts
        self._refresh_timeout = refresh_timeout
        self._is_mtls = False
        self._default_host = default_host
        self._auth_request = auth_request


    def configure_mtls_channel(self, client_cert_callback=None):
        """Configure the client certificate and key for SSL connection.

        The function does nothing unless `GOOGLE_API_USE_CLIENT_CERTIFICATE` is
        explicitly set to `true`. In this case if client certificate and key are
        successfully obtained (from the given client_cert_callback or from application
        default SSL credentials), a :class:`_MutualTlsAdapter` instance will be mounted
        to "https://" prefix.

        Args:
            client_cert_callback (Optional[Callable[[], (bytes, bytes)]]):
                The optional callback returns the client certificate and private
                key bytes both in PEM format.
                If the callback is None, application default SSL credentials
                will be used.

        Raises:
            google.auth.exceptions.MutualTLSChannelError: If mutual TLS channel
                creation failed for any reason.
        """
        use_client_cert = os.getenv(
            environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE, "false"
        )
        if use_client_cert != "true":
            self._is_mtls = False
            return

        try:
            import OpenSSL
        except ImportError as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(caught_exc)
            raise new_exc from caught_exc

        try:
            (
                self._is_mtls,
                cert,
                key,
            ) = google.auth.transport._mtls_helper.get_client_cert_and_key(
                client_cert_callback
            )

            if self._is_mtls:
                mtls_adapter = _MutualTlsAdapter(cert, key)
                self.mount("https://", mtls_adapter)
        except (
            exceptions.ClientCertError,
            ImportError,
            OpenSSL.crypto.Error,
        ) as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(caught_exc)
            raise new_exc from caught_exc


    @abc.abstractmethod
    def request(self, method, url, data=None, headers=None, max_allowed_time=None, timeout=_DEFAULT_TIMEOUT, **kwargs):
        raise NotImplementedError("Request must be implemented")

    
    @abc.abstractmethod
    def close(self):
        raise NotImplementedError("Close must be implemented")


    @property
    def is_mtls(self):
        """Indicates if the created SSL channel is mutual TLS."""
        return self._is_mtls
    
