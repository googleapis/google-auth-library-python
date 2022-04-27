# Copyright 2022 Google LLC
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

import base64
import ctypes

import mock
import pytest
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
import urllib3.contrib.pyopenssl

from google.auth import exceptions
from google.auth.transport import _custom_tls_signer

urllib3.contrib.pyopenssl.inject_into_urllib3()

ENTERPRISE_CERT = {
    "libs": {
        "signer_library": "/path/to/signer/lib",
        "offload_library": "/path/to/offload/lib",
    }
}


@pytest.mark.parametrize("enterprise_cert", [None, {}, {"libs": {}}])
def test_load_offload_lib_no_lib(enterprise_cert):
    with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
        _custom_tls_signer.load_offload_lib(enterprise_cert)

    assert excinfo.match("offload library is not set")


def test_load_offload_lib():
    with mock.patch("ctypes.CDLL", return_value=mock.MagicMock()):
        lib = _custom_tls_signer.load_offload_lib(ENTERPRISE_CERT)

    assert lib.CreateCustomKey.argtypes == [_custom_tls_signer.SIGN_CALLBACK_CTYPE]
    assert lib.CreateCustomKey.restype == _custom_tls_signer.CUSTOM_KEY_CTYPE
    assert lib.DestroyCustomKey.argtypes == [_custom_tls_signer.CUSTOM_KEY_CTYPE]


@pytest.mark.parametrize("enterprise_cert", [None, {}, {"libs": {}}])
def test_load_signer_lib_no_lib(enterprise_cert):
    with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
        _custom_tls_signer.load_signer_lib(enterprise_cert)

    assert excinfo.match("signer library is not set")


def test_load_signer_lib():
    with mock.patch("ctypes.CDLL", return_value=mock.MagicMock()):
        lib = _custom_tls_signer.load_signer_lib(ENTERPRISE_CERT)

    assert lib.SignForPython.restype == ctypes.c_int
    assert lib.SignForPython.argtypes == [
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]

    assert lib.GetCertPemForPython.restype == ctypes.c_int
    assert lib.GetCertPemForPython.argtypes == [ctypes.c_char_p, ctypes.c_int]


def test__compute_sha256_digest():
    to_be_signed = ctypes.create_string_buffer(b"foo")
    sig = _custom_tls_signer._compute_sha256_digest(to_be_signed, 4)

    assert (
        base64.b64encode(sig).decode() == "RG5gyEH8CAAh3lxgbt2PLPAHPO8p6i9+cn5dqHfUUYM="
    )


def test_get_sign_callback():
    # mock signer lib's SignForPython function
    mock_sig_len = 10
    mock_signer_lib = mock.MagicMock()
    mock_signer_lib.SignForPython.return_value = mock_sig_len

    # create a sign callback. The callback calls signer lib's SignForPython method
    sign_callback = _custom_tls_signer.get_sign_callback(mock_signer_lib)

    # mock the parameters used to call the sign callback
    to_be_signed = ctypes.create_string_buffer(b"foo")
    to_be_signed_len = 4
    mock_sig_array = bytearray(mock_sig_len)
    mock_sig_len_array = [0]

    # call the callback, make sure the signature len is returned via mock_sig_len_array[0]
    assert sign_callback(
        mock_sig_array, mock_sig_len_array, to_be_signed, to_be_signed_len
    )
    assert mock_sig_len_array[0] == mock_sig_len


def test_get_cert_no_cert():
    # mock signer lib's GetCertPemForPython function to return 0 to indicts
    # the cert doesn't exit (cert len = 0)
    mock_signer_lib = mock.MagicMock()
    mock_signer_lib.GetCertPemForPython.return_value = 0

    # call the get cert method
    with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
        _custom_tls_signer.get_cert(mock_signer_lib)

    assert excinfo.match("failed to get certificate")


def test_get_cert():
    # mock signer lib's GetCertPemForPython function
    mock_cert_len = 10
    mock_signer_lib = mock.MagicMock()
    mock_signer_lib.GetCertPemForPython.return_value = mock_cert_len

    # call the get cert method
    mock_cert = _custom_tls_signer.get_cert(mock_signer_lib)

    # make sure the signer lib's GetCertPemForPython is called twice, and the
    # mock_cert has length mock_cert_len
    assert mock_signer_lib.GetCertPemForPython.call_count == 2
    assert len(mock_cert) == mock_cert_len


def test_custom_tls_signer():
    offload_lib = mock.MagicMock()
    signer_lib = mock.MagicMock()

    # Test load_libraries method
    with mock.patch(
        "google.auth.transport._custom_tls_signer.load_signer_lib"
    ) as load_signer_lib:
        with mock.patch(
            "google.auth.transport._custom_tls_signer.load_offload_lib"
        ) as load_offload_lib:
            load_offload_lib.return_value = offload_lib
            load_signer_lib.return_value = signer_lib
            signer_object = _custom_tls_signer.CustomTlsSigner(ENTERPRISE_CERT)
            signer_object.load_libraries()
    assert signer_object._cert is None
    assert signer_object._enterprise_cert == ENTERPRISE_CERT
    assert signer_object._offload_lib == offload_lib
    assert signer_object._signer_lib == signer_lib

    # Test set_up_custom_key and set_up_ssl_context methods
    with mock.patch("google.auth.transport._custom_tls_signer.get_cert") as get_cert:
        with mock.patch(
            "google.auth.transport._custom_tls_signer.get_sign_callback"
        ) as get_sign_callback:
            get_cert.return_value = b"mock_cert"
            signer_object.set_up_custom_key()
            signer_object.attach_to_ssl_context(create_urllib3_context())
    get_cert.assert_called_once()
    get_sign_callback.assert_called_once()
    offload_lib.CreateCustomKey.assert_called_once()
    offload_lib.OffloadSigning.assert_called_once()


def test_custom_tls_signer_fail_to_offload():
    offload_lib = mock.MagicMock()
    signer_lib = mock.MagicMock()

    with mock.patch(
        "google.auth.transport._custom_tls_signer.load_signer_lib"
    ) as load_signer_lib:
        with mock.patch(
            "google.auth.transport._custom_tls_signer.load_offload_lib"
        ) as load_offload_lib:
            load_offload_lib.return_value = offload_lib
            load_signer_lib.return_value = signer_lib
            signer_object = _custom_tls_signer.CustomTlsSigner(ENTERPRISE_CERT)
            signer_object.load_libraries()

    # set the return value to be 0 which indicts offload fails
    offload_lib.OffloadSigning.return_value = 0

    with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
        with mock.patch(
            "google.auth.transport._custom_tls_signer.get_cert"
        ) as get_cert:
            with mock.patch(
                "google.auth.transport._custom_tls_signer.get_sign_callback"
            ):
                get_cert.return_value = b"mock_cert"
                signer_object.set_up_custom_key()
                signer_object.attach_to_ssl_context(create_urllib3_context())
    assert excinfo.match("failed to offload signing")


def test_custom_tls_signer_cleanup():
    offload_lib = mock.MagicMock()
    signer_lib = mock.MagicMock()

    with mock.patch(
        "google.auth.transport._custom_tls_signer.load_signer_lib"
    ) as load_signer_lib:
        with mock.patch(
            "google.auth.transport._custom_tls_signer.load_offload_lib"
        ) as load_offload_lib:
            load_offload_lib.return_value = offload_lib
            load_signer_lib.return_value = signer_lib
            signer_object = _custom_tls_signer.CustomTlsSigner(ENTERPRISE_CERT)
            signer_object.load_libraries()

    signer_object.cleanup()
    offload_lib.DestroyCustomKey.assert_not_called()

    signer_object._custom_key = mock.Mock()
    signer_object.cleanup()
    offload_lib.DestroyCustomKey.assert_called_with(signer_object._custom_key)
