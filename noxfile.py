# Copyright 2019 Google LLC
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

import nox

TEST_DEPENDENCIES = ["certifi",
        "flask",
        "mock",
        "oauth2client",
        "pytest",
        "pytest-cov",
        "pytest-localserver",
        "requests",
        "requests-oauthlib",
        "urllib3",
        "cryptography",
        "grpcio",
]

@nox.session(python="3.7")
def lint(session):
    session.install("flake8", "flake8-import-order", "docutils")
    session.install(".")
    session.run(
        "flake8",
        "--import-order-style=google",
        "--application-import-names=google,tests,system_tests",
        "google",
        "tests",
    )
    session.run(
        "python", "setup.py", "check", "--metadata", "--restructuredtext", "--strict"
    )


@nox.session(python=["2.7", "3.5", "3.6", "3.7"])
def unit(session):
    session.install(*TEST_DEPENDENCIES)
    session.install(".")
    session.run(
        "pytest", "--cov=google.auth", "--cov=google.oauth2", "--cov=tests", "tests"
    )

# nox can run python 2 sessions but needs to be invoked from python 3
@nox.session(python=["3.7"])
def system(session):
    session.install(*TEST_DEPENDENCIES)
    session.install(
        "nox",
    )
    session.install(".")
    session.chdir("system_tests")
    session.run("nox")


@nox.session(python="3.7")
def cover(session):
    session.install(*TEST_DEPENDENCIES)
    session.install(".")
    session.run(
        "pytest",
        "--cov=google.auth",
        "--cov=google.oauth2",
        "--cov=tests",
        "--cov-report=",
        "tests",
    )
    session.run("coverage", "report", "--show-missing", "--fail-under=100")


@nox.session(python="3.7")
def docgen(session):
    session.env["SPHINX_APIDOC_OPTIONS"] = "members,inherited-members,show-inheritance"
    session.install(*TEST_DEPENDENCIES)
    session.install("sphinx")
    session.install(".")
    session.run("rm", "-r", "docs/reference")
    session.run(
        "sphinx-apidoc",
        "--output-dir",
        "docs/reference",
        "--separate",
        "--module-first",
        "google",
    )


@nox.session(python="3.7")
def docs(session):
    session.install("sphinx", "-r", "docs/requirements-docs.txt")
    session.install(".")
    session.run("make", "-C", "docs", "html")


@nox.session(python="pypy")
def pypy(session):
    session.install(*TEST_DEPENDENCIES)
    session.install(".")
    session.run(
        "pytest", "--cov=google.auth", "--cov=google.oauth2", "--cov=tests", "tests"
    )


@nox.session(python="3.7")
def pytype(session):
    session.install(*TEST_DEPENDENCIES)
    session.install("pytype")
    session.install(".")
    session.run("pytype")
