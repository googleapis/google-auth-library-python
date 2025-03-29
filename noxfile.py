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

import os
import pathlib
import shutil
import tempfile
import typing
import nox

from contextlib import contextmanager

CURRENT_DIRECTORY = pathlib.Path(__file__).parent.absolute()
showcase_version = os.environ.get("SHOWCASE_VERSION", "0.35.0")

# https://github.com/psf/black/issues/2964, pin click version to 8.0.4 to
# avoid incompatiblity with black.
CLICK_VERSION = "click==8.0.4"
BLACK_VERSION = "black==19.3b0"
BLACK_PATHS = [
    "google",
    "tests",
    "tests_async",
    "noxfile.py",
    "setup.py",
    "docs/conf.py",
]


@nox.session(python="3.8")
def lint(session):
    session.install(
        "flake8", "flake8-import-order", "docutils", CLICK_VERSION, BLACK_VERSION
    )
    session.install("-e", ".")
    session.run("black", "--check", *BLACK_PATHS)
    session.run(
        "flake8",
        "--import-order-style=google",
        "--application-import-names=google,tests,system_tests",
        "google",
        "tests",
        "tests_async",
    )
    session.run(
        "python", "setup.py", "check", "--metadata", "--restructuredtext", "--strict"
    )


@nox.session(python="3.8")
def blacken(session):
    """Run black.
    Format code to uniform standard.
    The Python version should be consistent with what is
    supplied in the Python Owlbot postprocessor.

    https://github.com/googleapis/synthtool/blob/master/docker/owlbot/python/Dockerfile
    """
    session.install(CLICK_VERSION, BLACK_VERSION)
    session.run("black", *BLACK_PATHS)


@nox.session(python="3.8")
def mypy(session):
    """Verify type hints are mypy compatible."""
    session.install("-e", ".")
    session.install(
        "mypy",
        "types-cachetools",
        "types-certifi",
        "types-freezegun",
        "types-pyOpenSSL",
        "types-requests",
        "types-setuptools",
        "types-mock",
    )
    session.run("mypy", "-p", "google", "-p", "tests", "-p", "tests_async")


@nox.session(python=["3.7", "3.8", "3.9", "3.10", "3.11", "3.12"])
def unit(session):
    constraints_path = str(
        CURRENT_DIRECTORY / "testing" / f"constraints-{session.python}.txt"
    )
    session.install("-r", "testing/requirements.txt", "-c", constraints_path)
    session.install("-e", ".", "-c", constraints_path)
    session.run(
        "pytest",
        f"--junitxml=unit_{session.python}_sponge_log.xml",
        "--cov=google.auth",
        "--cov=google.oauth2",
        "--cov=tests",
        "--cov-report=term-missing",
        "tests",
        "tests_async",
    )


@nox.session(python="3.8")
def cover(session):
    session.install("-r", "testing/requirements.txt")
    session.install("-e", ".")
    session.run(
        "pytest",
        "--cov=google.auth",
        "--cov=google.oauth2",
        "--cov=tests",
        "--cov=tests_async",
        "--cov-report=term-missing",
        "tests",
        "tests_async",
    )
    session.run("coverage", "report", "--show-missing", "--fail-under=100")


@nox.session(python="3.9")
def docs(session):
    """Build the docs for this library."""

    session.install("-e", ".[aiohttp]")
    session.install("sphinx", "alabaster", "recommonmark", "sphinx-docstring-typing")

    shutil.rmtree(os.path.join("docs", "_build"), ignore_errors=True)
    session.run(
        "sphinx-build",
        "-T",  # show full traceback on exception
        "-W",  # warnings as errors
        "-N",  # no colors
        "-b",
        "html",
        "-d",
        os.path.join("docs", "_build", "doctrees", ""),
        os.path.join("docs", ""),
        os.path.join("docs", "_build", "html", ""),
    )


@nox.session(python="pypy")
def pypy(session):
    session.install("-r", "testing/requirements.txt")
    session.install("-e", ".")
    session.run(
        "pytest",
        f"--junitxml=unit_{session.python}_sponge_log.xml",
        "--cov=google.auth",
        "--cov=google.oauth2",
        "--cov=tests",
        "tests",
        "tests_async",
    )

@contextmanager
def showcase_library(
    session, templates="DEFAULT", other_opts: typing.Iterable[str] = (),
    include_service_yaml=True,
    retry_config=True,
    rest_async_io_enabled=False
):
    """Install the generated library into the session for showcase tests."""

    session.log("-" * 70)
    session.log("Note: Showcase must be running for these tests to work.")
    session.log("See https://github.com/googleapis/gapic-showcase")
    session.log("-" * 70)

    # Install gapic-generator-python
    session.install("-e", ".")

    # Install grpcio-tools for protoc
    session.install("grpcio-tools")

    # Install a client library for Showcase.
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Download the Showcase descriptor.
        session.run(
            "curl",
            "https://github.com/googleapis/gapic-showcase/blob/507a4cbdc45c8380aff29308ff2a1144ead9a7dc/test_gapic_showcase.desc"
            # "https://github.com/googleapis/gapic-showcase/releases/"
            # f"download/v{showcase_version}/"
            # f"gapic-showcase-{showcase_version}.desc",
            "-L",
            "--output",
            os.path.join(tmp_dir, "showcase.desc"),
            external=True,
            silent=True,
        )
        if include_service_yaml:
            session.run(
                "curl",
                "https://github.com/googleapis/gapic-showcase/blob/507a4cbdc45c8380aff29308ff2a1144ead9a7dc/schema/google/showcase/v1beta1/showcase_v1beta1.yaml",
                # "https://github.com/googleapis/gapic-showcase/releases/"
                # f"download/v{showcase_version}/"
                # f"showcase_v1beta1.yaml",
                "-L",
                "--output",
                os.path.join(tmp_dir, "showcase_v1beta1.yaml"),
                external=True,
                silent=True,
            )
            # TODO(https://github.com/googleapis/gapic-generator-python/issues/2121): The section below updates the showcase service yaml
            # to test experimental async rest transport. It must be removed once support for async rest is GA.
            if rest_async_io_enabled:
                # Install pyYAML for yaml.
                session.install("pyYAML")

                python_settings = [
                    {
                        'version': 'google.showcase.v1beta1',
                        'python_settings': {
                            'experimental_features': {
                                'rest_async_io_enabled': True
                            }
                        }
                    }
                ]
                update_service_yaml = _add_python_settings(tmp_dir, python_settings)
                session.run("python", "-c" f"{update_service_yaml}")
            # END TODO section to remove.
        if retry_config:
            session.run(
                "curl",
                "https://github.com/googleapis/gapic-showcase/blob/507a4cbdc45c8380aff29308ff2a1144ead9a7dc/schema/google/showcase/v1beta1/showcase_grpc_service_config.json",
                # "https://github.com/googleapis/gapic-showcase/releases/"
                # f"download/v{showcase_version}/"
                # f"showcase_grpc_service_config.json",
                "-L",
                "--output",
                os.path.join(tmp_dir, "showcase_grpc_service_config.json"),
                external=True,
                silent=True,
            )
        # Write out a client library for Showcase.
        template_opt = f"python-gapic-templates={templates}"
        opts = "--python_gapic_opt="
        if include_service_yaml and retry_config:
            opts += ",".join(other_opts + (f"{template_opt}", "transport=grpc+rest", f"service-yaml=/usr/local/google/home/saisunder/data/playground/TestingStrategy/gapic-showcase/schema/google/showcase/v1beta1/showcase_v1beta1.yaml", f"retry-config=/usr/local/google/home/saisunder/data/playground/TestingStrategy/gapic-showcase/schema/google/showcase/v1beta1/showcase_grpc_service_config.json"))
        else:
            opts += ",".join(other_opts + (f"{template_opt}", "transport=grpc+rest",))            
        cmd_tup = (
            "python",
            "-m",
            "grpc_tools.protoc",
            f"--experimental_allow_proto3_optional",
            f"--descriptor_set_in=/usr/local/google/home/saisunder/data/playground/TestingStrategy/gapic-showcase/test_gapic_showcase.desc",
            opts,
            f"--python_gapic_out={tmp_dir}",
            f"google/showcase/v1beta1/echo.proto",
            f"google/showcase/v1beta1/identity.proto",
            f"google/showcase/v1beta1/messaging.proto",
        )
        session.run(
            *cmd_tup, external=True,
        )

        # Install the generated showcase library.
        if templates == "DEFAULT":
            # Use the constraints file for the specific python runtime version.
            # We do this to make sure that we're testing against the lowest
            # supported version of a dependency.
            # This is needed to recreate the issue reported in
            # https://github.com/googleapis/google-cloud-python/issues/12254
            constraints_path = str(
            f"{tmp_dir}/testing/constraints-{session.python}.txt"
            )
            # Install the library with a constraints file.
            session.install("-e", tmp_dir, "-r", constraints_path)
        else:
            # The ads templates do not have constraints files.
            # See https://github.com/googleapis/gapic-generator-python/issues/1788
            # Install the library without a constraints file.
            session.install("-e", tmp_dir)

        yield tmp_dir


@nox.session(python="3.8")
def showcase(
    session,
    templates="DEFAULT",
    other_opts: typing.Iterable[str] = (),
    env: typing.Optional[typing.Dict[str, str]] = {},
):
    """Run the Showcase test suite."""

    with showcase_library(session, templates=templates, other_opts=other_opts):
        session.install("pytest", "pytest-asyncio", "mock")
        test_directory = os.path.join("tests", "showcase")
        ignore_file = env.get("IGNORE_FILE")
        pytest_command = [
            "py.test",
            "--quiet",
            *(session.posargs or [str(test_directory)]),
        ]
        if ignore_file:
            ignore_path = test_directory / ignore_file
            pytest_command.extend(["--ignore", str(ignore_path)])

        session.run(
            *pytest_command,
            env=env,
        )

# `_add_python_settings` consumes a path to a temporary directory (str; i.e. tmp_dir) and 
# python settings (Dict; i.e. python settings) and modifies the service yaml within 
# tmp_dir to include python settings. The primary purpose of this function is to modify 
# the service yaml and include `rest_async_io_enabled=True` to test the async rest
# optional feature.
def _add_python_settings(tmp_dir, python_settings):
    return f"""
import yaml
from pathlib import Path
temp_file_path = Path(f"/usr/local/google/home/saisunder/data/playground/TestingStrategy/gapic-showcase/schema/google/showcase/v1beta1/showcase_v1beta1.yaml")
with temp_file_path.open('r') as file:
    data = yaml.safe_load(file)
    data['publishing']['library_settings'] = {python_settings}

with temp_file_path.open('w') as file:
    yaml.safe_dump(data, file, default_flow_style=False, sort_keys=False)
"""