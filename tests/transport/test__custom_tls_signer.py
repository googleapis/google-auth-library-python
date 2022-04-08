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
import os

import mock
import pytest
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
import urllib3.contrib.pyopenssl

from google.auth import environment_vars, exceptions
from google.auth.transport import _custom_tls_signer

urllib3.contrib.pyopenssl.inject_into_urllib3()

PKCS11_KEY = {
    "type": "pkcs11",
    "key_info": {
        "module_path": "/usr/local/lib/libfoo.so",
        "token_label": "token1",
        "key_label": "key1",
    },
}

MACOS_KEYCHAIN_KEY = {"type": "macos_keychain", "key_info": {"issuer": "localhost"}}

WINDOWS_CERT_STORE_KEY = {
    "type": "windows_cert_store",
    "key_info": {"provider": "current_user", "store_name": "MY", "issuer": "localhost"},
}

INVALID_KEY = {"type": "foo"}


def test_validate_key_format_with_invalid_key():
    with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
        _custom_tls_signer.validate_key_format(INVALID_KEY)

    assert excinfo.match("key type foo is not supported")


@mock.patch.dict(os.environ, {}, clear=True)
def test_load_offload_lib_no_lib():
    with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
        _custom_tls_signer.load_offload_lib()

    assert excinfo.match("GOOGLE_AUTH_OFFLOAD_LIBRARY_PATH is not set")


@mock.patch.dict(os.environ)
def test_load_offload_lib():
    os.environ[
        environment_vars.GOOGLE_AUTH_OFFLOAD_LIBRARY_PATH
    ] = "/path/to/offload/lib"
    with mock.patch("ctypes.CDLL", return_value=mock.MagicMock()):
        lib = _custom_tls_signer.load_offload_lib()

    assert lib.CreateCustomKey.argtypes == [_custom_tls_signer.SIGN_CALLBACK_CTYPE]
    assert lib.CreateCustomKey.restype == _custom_tls_signer.CUSTOM_KEY_CTYPE
    assert lib.DestroyCustomKey.argtypes == [_custom_tls_signer.CUSTOM_KEY_CTYPE]


@mock.patch.dict(os.environ, {}, clear=True)
def test_load_signer_lib_no_lib():
    with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
        _custom_tls_signer.load_signer_lib(MACOS_KEYCHAIN_KEY)

    assert excinfo.match("GOOGLE_AUTH_SIGNER_LIBRARY_PATH is not set")


@mock.patch.dict(os.environ, {}, clear=True)
def test_load_signer_lib_pkcs11_key():
    assert _custom_tls_signer.load_signer_lib(PKCS11_KEY) is None


@mock.patch.dict(os.environ)
def test_load_signer_lib_windows_cert_store_key():
    os.environ[environment_vars.GOOGLE_AUTH_SIGNER_LIBRARY_PATH] = "/path/to/lib"
    with mock.patch("ctypes.CDLL", return_value=mock.MagicMock()):
        lib = _custom_tls_signer.load_signer_lib(WINDOWS_CERT_STORE_KEY)

    assert lib.SignForPython.restype == ctypes.c_int
    assert lib.SignForPython.argtypes == [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]

    assert lib.GetCertPemForPython.restype == ctypes.c_int
    assert lib.GetCertPemForPython.argtypes == [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
    ]


@mock.patch.dict(os.environ)
def test_load_signer_lib_macos_keychain_key():
    os.environ[environment_vars.GOOGLE_AUTH_SIGNER_LIBRARY_PATH] = "/path/to/lib"
    with mock.patch("ctypes.CDLL", return_value=mock.MagicMock()):
        lib = _custom_tls_signer.load_signer_lib(MACOS_KEYCHAIN_KEY)

    assert lib.SignForPython.restype == ctypes.c_int
    assert lib.SignForPython.argtypes == [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]

    assert lib.GetCertPemForPython.restype == ctypes.c_int
    assert lib.GetCertPemForPython.argtypes == [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
    ]


def test__compute_sha256_digest():
    to_be_signed = ctypes.create_string_buffer(b"foo")
    sig = _custom_tls_signer._compute_sha256_digest(to_be_signed, 4)

    assert (
        base64.b64encode(sig).decode() == "RG5gyEH8CAAh3lxgbt2PLPAHPO8p6i9+cn5dqHfUUYM="
    )


def test__get_pkcs11_sign_callback():
    # todo
    pass


@pytest.mark.parametrize(
    "mock_key, get_sign_callback_method",
    [
        (WINDOWS_CERT_STORE_KEY, _custom_tls_signer._get_win_cert_store_sign_callback),
        (MACOS_KEYCHAIN_KEY, _custom_tls_signer._get_macos_keychain_sign_callback),
    ],
)
def test__get_win_and_mac_sign_callback(mock_key, get_sign_callback_method):
    # mock signer lib's SignForPython function
    mock_sig_len = 10
    mock_signer_lib = mock.MagicMock()
    mock_signer_lib.SignForPython.return_value = mock_sig_len

    # create a sign callback. The callback calls signer lib's SignForPython method
    sign_callback = get_sign_callback_method(mock_key, mock_signer_lib)

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


def test_get_sign_callback_pkcs11():
    with mock.patch(
        "google.auth.transport._custom_tls_signer._get_pkcs11_sign_callback"
    ) as mock_get_pkcs11_sign_callback:
        _custom_tls_signer.get_sign_callback(PKCS11_KEY, None)
        mock_get_pkcs11_sign_callback.assert_called_once_with(PKCS11_KEY)


def test_get_sign_callback_windows_cert_store():
    with mock.patch(
        "google.auth.transport._custom_tls_signer._get_win_cert_store_sign_callback"
    ) as mock_get_win_cert_store_sign_callback:
        signer_lib = mock.Mock()
        _custom_tls_signer.get_sign_callback(WINDOWS_CERT_STORE_KEY, signer_lib)
        mock_get_win_cert_store_sign_callback.assert_called_once_with(
            WINDOWS_CERT_STORE_KEY, signer_lib
        )


def test_get_sign_callback_macos_keychain():
    with mock.patch(
        "google.auth.transport._custom_tls_signer._get_macos_keychain_sign_callback"
    ) as mock_get_macos_keychain_sign_callback:
        signer_lib = mock.Mock()
        _custom_tls_signer.get_sign_callback(MACOS_KEYCHAIN_KEY, signer_lib)
        mock_get_macos_keychain_sign_callback.assert_called_once_with(
            MACOS_KEYCHAIN_KEY, signer_lib
        )


def test__get_cert_from_pkcs11():
    # todo
    pass


@pytest.mark.parametrize(
    "mock_key, get_cert_method",
    [
        (WINDOWS_CERT_STORE_KEY, _custom_tls_signer._get_cert_from_windows_cert_store),
        (MACOS_KEYCHAIN_KEY, _custom_tls_signer._get_cert_from_macos_keychain),
    ],
)
def test__get_cert_from_win_and_mac(mock_key, get_cert_method):
    # mock signer lib's GetCertPemForPython function
    mock_cert_len = 10
    mock_signer_lib = mock.MagicMock()
    mock_signer_lib.GetCertPemForPython.return_value = mock_cert_len

    # call the get cert method
    mock_cert = get_cert_method(mock_key, mock_signer_lib)

    # make sure the signer lib's GetCertPemForPython is called twice, and the
    # mock_cert has length mock_cert_len
    assert mock_signer_lib.GetCertPemForPython.call_count == 2
    assert len(mock_cert) == mock_cert_len


@pytest.mark.parametrize(
    "mock_key, get_cert_method",
    [
        (WINDOWS_CERT_STORE_KEY, _custom_tls_signer._get_cert_from_windows_cert_store),
        (MACOS_KEYCHAIN_KEY, _custom_tls_signer._get_cert_from_macos_keychain),
    ],
)
def test__get_cert_from_win_and_mac_failed(mock_key, get_cert_method):
    # mock signer lib's GetCertPemForPython function to return 0, which
    # means it fails to get cert.
    mock_signer_lib = mock.MagicMock()
    mock_signer_lib.GetCertPemForPython.return_value = 0

    with pytest.raises(exceptions.MutualTLSChannelError) as excinfo:
        # call the get cert method
        get_cert_method(mock_key, mock_signer_lib)
    assert excinfo.match("failed to get certificate")


def test_get_cert_pkcs11():
    with mock.patch(
        "google.auth.transport._custom_tls_signer._get_cert_from_pkcs11"
    ) as _get_cert_from_pkcs11:
        _custom_tls_signer.get_cert(PKCS11_KEY, None)
        _get_cert_from_pkcs11.assert_called_once_with(PKCS11_KEY)


def test_get_cert_windows_cert_store():
    with mock.patch(
        "google.auth.transport._custom_tls_signer._get_cert_from_windows_cert_store"
    ) as _get_cert_from_windows_cert_store:
        signer_lib = mock.Mock()
        _custom_tls_signer.get_cert(WINDOWS_CERT_STORE_KEY, signer_lib)
        _get_cert_from_windows_cert_store.assert_called_once_with(
            WINDOWS_CERT_STORE_KEY, signer_lib
        )


def test_get_cert_macos_keychain():
    with mock.patch(
        "google.auth.transport._custom_tls_signer._get_cert_from_macos_keychain"
    ) as _get_cert_from_macos_keychain:
        signer_lib = mock.Mock()
        _custom_tls_signer.get_cert(MACOS_KEYCHAIN_KEY, signer_lib)
        _get_cert_from_macos_keychain.assert_called_once_with(
            MACOS_KEYCHAIN_KEY, signer_lib
        )


def test_custom_tls_signer():
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
            signer_object = _custom_tls_signer.CustomTlsSigner(
                None, WINDOWS_CERT_STORE_KEY
            )
    assert signer_object.cert is None
    assert signer_object.key == WINDOWS_CERT_STORE_KEY
    assert signer_object.offload_lib == offload_lib
    assert signer_object.signer_lib == signer_lib

    with mock.patch("google.auth.transport._custom_tls_signer.get_cert") as get_cert:
        with mock.patch(
            "google.auth.transport._custom_tls_signer.get_sign_callback"
        ) as get_sign_callback:
            get_cert.return_value = b"mock_cert"
            signer_object.set_up_ssl_context(create_urllib3_context())
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
            signer_object = _custom_tls_signer.CustomTlsSigner(
                None, WINDOWS_CERT_STORE_KEY
            )

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
                signer_object.set_up_ssl_context(create_urllib3_context())
    assert excinfo.match("failed to offload signing")
