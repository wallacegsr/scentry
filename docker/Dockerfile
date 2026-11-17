# syntax=docker/dockerfile:1
# Two images from one file:
#   --target web     the portal: Python and the app, no scanners, no git
#   --target runner  the app plus every scanner; this is the one that reads hostile code
#
# Debian, not Alpine: Semgrep and GuardDog ship manylinux wheels only, and nothing here
# is compiled. Python 3.13 because Barkley needs it.
ARG PYTHON_IMAGE=python:3.13-slim-trixie

# --- the app itself, in a venv both images copy ----------------------------------------
FROM ${PYTHON_IMAGE} AS app
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m venv /opt/scentry \
    && /opt/scentry/bin/pip install --no-cache-dir --disable-pip-version-check . \
    && python -m compileall -q /opt/scentry

# --- web -------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS web
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
COPY --from=app /opt/scentry /opt/scentry
ENV PATH=/opt/scentry/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]
CMD ["scentry", "web"]

# --- scanner tools, every version pinned -----------------------------------------------
FROM ${PYTHON_IMAGE} AS tools
ARG TARGETARCH
# Release binaries: bumping a version means updating its sha256 pair below.
ARG UV_VERSION=0.13.7
ARG OSV_SCANNER_VERSION=2.7.1
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.76.2
# Python tools, each in its own venv.
ARG SEMGREP_VERSION=1.185.0
ARG GUARDDOG_VERSION=3.2.0
ARG BANDIT_VERSION=1.9.4
ARG ZIZMOR_VERSION=1.32.0
# Barkley isn't on PyPI: installed from its repository at an exact commit (v0.13.0).
ARG BARKLEY_COMMIT=e7a8c8bd6ccfc53e34b3cfb205fe2f9cec260940

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) uv_arch=x86_64; gl_arch=x64; tv_arch=64bit; \
        uv_sha=287491da03f2a785c70fa75b13e1f849918c2f2b5415fe84876b8214eeb792f9; \
        osv_sha=fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8; \
        gl_sha=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb; \
        tv_sha=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf ;; \
      arm64) uv_arch=aarch64; gl_arch=arm64; tv_arch=ARM64; \
        uv_sha=2d3ec076a0c4c0e8250bb6418c44080828b544f1a3be0b6e46adf9fb6923de45; \
        osv_sha=983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81; \
        gl_sha=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080; \
        tv_sha=ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3 ;; \
      *) echo "unsupported architecture '${TARGETARCH}'"; exit 1 ;; \
    esac; \
    get() { curl -fsSL --retry 3 --retry-all-errors --retry-delay 3 -o "$1" "$2"; \
            echo "$3  $1" | sha256sum -c -; }; \
    get /tmp/uv.tgz "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${uv_arch}-unknown-linux-musl.tar.gz" "${uv_sha}"; \
    tar -xzf /tmp/uv.tgz -C /usr/local/bin --strip-components=1 --wildcards '*/uv'; \
    get /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${TARGETARCH}" "${osv_sha}"; \
    get /tmp/gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" "${gl_sha}"; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    get /tmp/trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${tv_arch}.tar.gz" "${tv_sha}"; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    chmod 0755 /usr/local/bin/uv /usr/local/bin/osv-scanner /usr/local/bin/gitleaks /usr/local/bin/trivy; \
    rm -f /tmp/*.tgz

ENV UV_TOOL_DIR=/opt/tools \
    UV_TOOL_BIN_DIR=/opt/tools/bin \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1
# Wheels only (--no-build): no setup.py runs while the image is built.
RUN uv tool install --no-build "semgrep==${SEMGREP_VERSION}" \
    && uv tool install --no-build "guarddog==${GUARDDOG_VERSION}" \
    && uv tool install --no-build "bandit[sarif]==${BANDIT_VERSION}" \
    && uv tool install --no-build "zizmor==${ZIZMOR_VERSION}"
# Barkley is built from source here (pure Python, hatchling), so this one step builds.
RUN uv tool install "git+https://github.com/SeriesOfTubez/ha-barkley@${BARKLEY_COMMIT}" \
    && python -m compileall -q /opt/tools || true

# --- runner ----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runner
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 10001 -g 10001 /cache /work
COPY --from=tools /usr/local/bin/uv /usr/local/bin/osv-scanner /usr/local/bin/gitleaks /usr/local/bin/trivy /usr/local/bin/
COPY --from=tools /opt/tools /opt/tools
COPY --from=app /opt/scentry /opt/scentry
# HOME and every tool cache live on the /cache volume; the root filesystem is read-only.
ENV PATH=/opt/scentry/bin:/opt/tools/bin:$PATH \
    HOME=/cache \
    XDG_CACHE_HOME=/cache \
    SCENTRY_WORK_DIR=/work \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PYTHON_DOWNLOADS=never \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0
USER 10001:10001
CMD ["scentry", "worker"]
