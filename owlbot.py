import synthtool as s
from synthtool import gcp

common = gcp.CommonTemplates()

# ----------------------------------------------------------------------------
# Add templated files
# ----------------------------------------------------------------------------
templated_files = common.py_library(unit_cov_level=100, cov_level=100)


s.move(
    templated_files / ".kokoro",
    excludes=[
        "continuous/common.cfg",
        "docs/common.cfg",
        "docker/docs/Dockerfile", # XXX wait
        "presubmit/common.cfg",
        "build.sh",
    ],
)  # just move kokoro configs


assert 1 == s.replace(
    ".kokoro/docs/docs-presubmit.cfg",
    'value: "docs docfx"',
    'value: "docs"',
)

if 0:  # XXX wait until we test it before trying to repllce
    assert 1 == s.replace(
        ".kokoro/docker/docs/Dockerfile",
        """\
CMD ["python3.8"]""",
        """\
# Install gcloud SDK
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | \
     sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
  && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | \
     sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
  && sudo apt-get update \
  && sudo apt-get install google-cloud-sdk

CMD ["python3.8"]""",
    )

s.shell.run(["nox", "-s", "blacken"], hide_output=False)
