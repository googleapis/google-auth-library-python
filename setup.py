# Copyright 2014 Google Inc.
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

import io
import json
import os
import platform

from setuptools import Extension
from setuptools import find_packages
from setuptools import setup


DEPENDENCIES = (
    "cachetools>=2.0.0,<5.0",
    "pyasn1-modules>=0.2.1",
    # rsa==4.5 is the last version to support 2.7
    # https://github.com/sybrenstuvel/python-rsa/issues/152#issuecomment-643470233
    'rsa<4.6; python_version < "3.6"',
    'rsa>=3.1.4,<5; python_version >= "3.6"',
    # install enum34 to support 2.7. enum34 only works up to python version 3.3.
    'enum34>=1.1.10; python_version < "3.4"',
    "setuptools>=40.3.0",
    "six>=1.9.0",
)

extras = {
    "aiohttp": [
        "aiohttp >= 3.6.2, < 4.0.0dev; python_version>='3.6'",
        "requests >= 2.20.0, < 3.0.0dev",
    ],
    "pyopenssl": "pyopenssl>=20.0.0",
    "reauth": "pyu2f>=0.1.5",
}

with io.open("README.rst", "r") as fh:
    long_description = fh.read()

package_root = os.path.abspath(os.path.dirname(__file__))

version = {}
with open(os.path.join(package_root, "google/auth/version.py")) as fp:
    exec(fp.read(), version)
version = version["__version__"]

# To build this extension,
# On Linux/MacOS, run
#     CC=g++ GOOGLE_AUTH_BUILD_TLS_OFFLOAD=1 python -m pip install .
# On Windows, run
#     $env:GOOGLE_AUTH_BUILD_TLS_OFFLOAD=1
#     python -m pip install .
# You may also need to provide the include/library path for OpenSSL.
# The OpenSSL version has to be 1.1.
#     GOOGLE_AUTH_BUILD_INCLUDE_DIR = '["/usr/local/opt/openssl@1.1/include"]'
#     GOOGLE_AUTH_BUILD_LIB_DIR = '["/usr/local/opt/openssl@1.1/lib"]'
BUILD_TLS_OFFLOAD = os.getenv("GOOGLE_AUTH_BUILD_TLS_OFFLOAD")
BUILD_INC_DIR = os.getenv("GOOGLE_AUTH_BUILD_INCLUDE_DIR")
BUILD_LIB_DIR = os.getenv("GOOGLE_AUTH_BUILD_LIB_DIR")
ext_module = None
extra_compile_args = None if platform.system() == "Windows" else ['-std=c++11']
libraries = ["libcrypto", "libssl"] if platform.system() == "Windows" else ["crypto", "ssl"]
include_dirs = json.loads(BUILD_INC_DIR) if BUILD_INC_DIR else None
library_dirs = json.loads(BUILD_LIB_DIR) if BUILD_LIB_DIR else None
if BUILD_TLS_OFFLOAD:
    tls_offload_ext = Extension(
        name="tls_offload_ext",
        language="c++",
        libraries=libraries,
        sources=["google/auth/transport/cpp/tls_offload.cpp"],
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        extra_compile_args=extra_compile_args,
    )
    ext_module = [tls_offload_ext]

setup(
    name="google-auth",
    version=version,
    author="Google Cloud Platform",
    author_email="googleapis-packages@google.com",
    description="Google Authentication Library",
    long_description=long_description,
    url="https://github.com/googleapis/google-auth-library-python",
    packages=find_packages(exclude=("tests*", "system_tests*")),
    namespace_packages=("google",),
    install_requires=DEPENDENCIES,
    extras_require=extras,
    python_requires=">=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*,!=3.5.*",
    license="Apache 2.0",
    keywords="google auth oauth client",
    ext_modules=ext_module,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: OS Independent",
        "Topic :: Internet :: WWW/HTTP",
    ],
)
