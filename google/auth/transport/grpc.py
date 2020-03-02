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

"""Authorization support for gRPC."""

from __future__ import absolute_import

from concurrent import futures
import logging

import six

from google.auth.transport import _mtls_helper

try:
    import grpc
except ImportError as caught_exc:  # pragma: NO COVER
    six.raise_from(
        ImportError(
            "gRPC is not installed, please install the grpcio package "
            "to use the gRPC transport."
        ),
        caught_exc,
    )

_LOGGER = logging.getLogger(__name__)


class AuthMetadataPlugin(grpc.AuthMetadataPlugin):
    """A `gRPC AuthMetadataPlugin`_ that inserts the credentials into each
    request.

    .. _gRPC AuthMetadataPlugin:
        http://www.grpc.io/grpc/python/grpc.html#grpc.AuthMetadataPlugin

    Args:
        credentials (google.auth.credentials.Credentials): The credentials to
            add to requests.
        request (google.auth.transport.Request): A HTTP transport request
            object used to refresh credentials as needed.
    """

    def __init__(self, credentials, request):
        # pylint: disable=no-value-for-parameter
        # pylint doesn't realize that the super method takes no arguments
        # because this class is the same name as the superclass.
        super(AuthMetadataPlugin, self).__init__()
        self._credentials = credentials
        self._request = request
        self._pool = futures.ThreadPoolExecutor(max_workers=1)

    def _get_authorization_headers(self, context):
        """Gets the authorization headers for a request.

        Returns:
            Sequence[Tuple[str, str]]: A list of request headers (key, value)
                to add to the request.
        """
        headers = {}
        self._credentials.before_request(
            self._request, context.method_name, context.service_url, headers
        )

        return list(six.iteritems(headers))

    @staticmethod
    def _callback_wrapper(callback):
        def wrapped(future):
            callback(future.result(), None)

        return wrapped

    def __call__(self, context, callback):
        """Passes authorization metadata into the given callback.

        Args:
            context (grpc.AuthMetadataContext): The RPC context.
            callback (grpc.AuthMetadataPluginCallback): The callback that will
                be invoked to pass in the authorization metadata.
        """
        future = self._pool.submit(self._get_authorization_headers, context)
        future.add_done_callback(self._callback_wrapper(callback))

    def __del__(self):
        self._pool.shutdown(wait=False)


def secure_authorized_channel(
    credentials,
    request,
    target,
    ssl_credentials=None,
    client_cert_callback=None,
    **kwargs
):
    """Creates a secure authorized gRPC channel.

    This creates a channel with SSL and :class:`AuthMetadataPlugin`. This
    channel can be used to create a stub that can make authorized requests.

    Example::

        import google.auth
        import google.auth.transport.grpc
        import google.auth.transport.requests
        from google.cloud.speech.v1 import cloud_speech_pb2

        # Get credentials.
        credentials, _ = google.auth.default()

        # Get an HTTP request function to refresh credentials.
        request = google.auth.transport.requests.Request()

        # Create a channel.
        channel = google.auth.transport.grpc.secure_authorized_channel(
            credentials, 'speech.googleapis.com:443', request)

        # Use the channel to create a stub.
        cloud_speech.create_Speech_stub(channel)

    Args:
        credentials (google.auth.credentials.Credentials): The credentials to
            add to requests.
        request (google.auth.transport.Request): A HTTP transport request
            object used to refresh credentials as needed. Even though gRPC
            is a separate transport, there's no way to refresh the credentials
            without using a standard http transport.
        target (str): The host and port of the service.
        ssl_credentials (grpc.ChannelCredentials): Optional SSL channel
            credentials. This can be used to specify different certificates.
            This argument is mutually exclusive with client_cert_callback;
            providing both will raise an exception.
            If ssl_credentials is None and client_cert_callback is None or
            fails, application default SSL credentials will be used.
        client_cert_callback (Callable[[], (bool, bytes, bytes)]): Optional
            callback function to obtain client certicate and key for mutual TLS
            connection. This argument is mutually exclusive with
            ssl_credentials; providing both will raise an exception.
            If ssl_credentials is None and client_cert_callback is None or
            fails, application default SSL credentials will be used.
        kwargs: Additional arguments to pass to :func:`grpc.secure_channel`.

    Returns:
        grpc.Channel: The created gRPC channel.

    Raises:
        OSError: cert provider command launch failure, in application default SSL
            credentials loading process on devices with endpoint verification
            support.
        RuntimeError: cert provider command runtime error, in application
            default SSL credentials loading process on devices with endpoint
            verification support.
        ValueError:
            if context aware metadata file is malformed, or cert provider
            command doesn't produce both client certicate and key, in application
            default SSL credentials loading process on devices with endpoint
            verification support.
    """
    # Create the metadata plugin for inserting the authorization header.
    metadata_plugin = AuthMetadataPlugin(credentials, request)

    # Create a set of grpc.CallCredentials using the metadata plugin.
    google_auth_credentials = grpc.metadata_call_credentials(metadata_plugin)

    if ssl_credentials and client_cert_callback:
        raise ValueError(
            "Received both ssl_credentials and client_cert_callback; "
            "these are mutually exclusive."
        )

    if client_cert_callback:
        success, cert, key = client_cert_callback()
        if success:
            ssl_credentials = grpc.ssl_channel_credentials(
                certificate_chain=cert, private_key=key
            )

    if ssl_credentials is None:
        adc_ssl_credentils = SslCredentials()
        ssl_credentials = adc_ssl_credentils.ssl_credentials

    # Combine the ssl credentials and the authorization credentials.
    composite_credentials = grpc.composite_channel_credentials(
        ssl_credentials, google_auth_credentials
    )

    return grpc.secure_channel(target, composite_credentials, **kwargs)


class SslCredentials:
    """Class for application default SSL credentials.

    For device with endpoint verification support, device certificate will be
    automatically loaded and mutual TLS will be established.
    See https://cloud.google.com/endpoint-verification/docs/overview.
    """

    def __init__(self):
        # Load client SSL credentials.
        self._context_aware_metadata_path = _mtls_helper._check_dca_metadata_path(
            _mtls_helper.CONTEXT_AWARE_METADATA_PATH
        )
        if self._context_aware_metadata_path:
            self._is_mtls = True
        else:
            self._is_mtls = False

    @property
    def ssl_credentials(self):
        """Get the created SSL channel credentials.

        For device with endpoint verification support, if device certificate
        loading has any problems, corresponding exceptions will be raised. For
        device without endpoint verification support, no exceptions will be
        raised.

        Raises:
            OSError: cert provider command launch failure
            RuntimeError: cert provider command runtime error
            ValueError:
                if context aware metadata file is malformed, or cert provider
                command doesn't produce both client certicate and key.
        """
        if self._context_aware_metadata_path:
            metadata = _mtls_helper._read_dca_metadata_file(
                self._context_aware_metadata_path
            )
            cert, key = _mtls_helper.get_client_ssl_credentials(metadata)
            self._ssl_credentials = grpc.ssl_channel_credentials(
                certificate_chain=cert, private_key=key
            )
        else:
            self._ssl_credentials = grpc.ssl_channel_credentials()

        return self._ssl_credentials

    @property
    def is_mtls(self):
        """Property indicting if the created SSL channel credentials is mutual TLS."""
        return self._is_mtls
