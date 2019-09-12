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
        "gapic-google-cloud-pubsub-v1==0.15.0",
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
