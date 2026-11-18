# syntax=docker/dockerfile:1
# Two images from one file:
#   --target web     the portal: Python and the app, no scanners, no git
#   --target runner  the app plus every scanner; this is the one that reads hostile code
#
# Debian, not Alpine: Semgrep and GuardDog ship manylinux wheels only, and nothing here
# is compiled. Python 3.13 because Barkley needs it. Base images are pinned by digest
# (Dependabot moves them); every Python stage uses the same one.

# --- uv, checked against its sha256 -----------------------------------------------------
# Also what docker/tools/lock.sh runs in (hence git: Barkley comes from its repository).
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS uv
ARG TARGETARCH
ARG UV_VERSION=0.13.7
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) arch=x86_64; sha=287491da03f2a785c70fa75b13e1f849918c2f2b5415fe84876b8214eeb792f9 ;; \
      arm64) arch=aarch64; sha=2d3ec076a0c4c0e8250bb6418c44080828b544f1a3be0b6e46adf9fb6923de45 ;; \
      *) echo "unsupported architecture '${TARGETARCH}'"; exit 1 ;; \
    esac; \
    curl -fsSL --retry 3 --retry-all-errors --retry-delay 3 -o /tmp/uv.tgz \
      "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${arch}-unknown-linux-musl.tar.gz"; \
    echo "${sha}  /tmp/uv.tgz" | sha256sum -c -; \
    tar -xzf /tmp/uv.tgz -C /usr/local/bin --strip-components=1 --wildcards '*/uv'; \
    chmod 0755 /usr/local/bin/uv; rm -f /tmp/uv.tgz

# --- the app itself, in a venv both images copy ----------------------------------------
# Its dependencies come from uv.lock, each file checked against the hash recorded there.
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS app
COPY --from=uv /usr/local/bin/uv /usr/local/bin/uv
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
ENV UV_PROJECT_ENVIRONMENT=/opt/scentry \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
RUN uv sync --frozen --no-dev --no-editable --python /usr/local/bin/python3

# --- web -------------------------------------------------------------------------------
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS web
# Without pip: nothing here runs it, and the urllib3 and msgpack copies inside it go stale.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/bin/pip* /usr/local/lib/python3.13/site-packages/pip \
      /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
      /usr/local/lib/python3.13/ensurepip/_bundled
COPY --from=app /opt/scentry /opt/scentry
ENV PATH=/opt/scentry/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]
CMD ["scentry", "web"]

# --- gitleaks, built from its release commit with a current Go ---------------------------
# Its release binaries are built with an old Go and old x/crypto, x/text and compress,
# each with fixable CVEs; the same source built with current ones has none of them.
# (Left: rardecode, whose fix gitleaks' archive library can't take yet. Archives are
# only read with --max-archive-depth, which Scentry doesn't pass.)
# Modules are checked against Go's checksum database (sum.golang.org) as they download.
FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS gitleaks
ARG TARGETOS
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_COMMIT=83d9cd684c87d95d656c1458ef04895a7f1cbd8e
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
WORKDIR /src
RUN git init -q && git fetch -q --depth 1 https://github.com/gitleaks/gitleaks "${GITLEAKS_COMMIT}" \
    && git checkout -q FETCH_HEAD
RUN go get golang.org/x/crypto@v0.58.0 golang.org/x/text@v0.43.0 \
      github.com/klauspost/compress@v1.20.3 github.com/ulikunitz/xz@v0.5.15 \
    && GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /out/gitleaks \
      -ldflags "-s -w -X=github.com/zricethezav/gitleaks/v8/version.Version=v${GITLEAKS_VERSION}" .

# --- scanner tools, every version pinned -----------------------------------------------
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS tools
ARG TARGETARCH
# Release binaries: bumping a version means updating its sha256 pair below. (gitleaks is
# built in its own stage, above.)
ARG OSV_SCANNER_VERSION=2.7.1
ARG TRIVY_VERSION=0.76.2
# The Python tools (Semgrep, GuardDog, Bandit, zizmor, Barkley) are pinned in
# docker/tools/<name>/, with everything they need in its uv.lock.

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=uv /usr/local/bin/uv /usr/local/bin/uv

RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) tv_arch=64bit; \
        osv_sha=fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8; \
        tv_sha=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf ;; \
      arm64) tv_arch=ARM64; \
        osv_sha=983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81; \
        tv_sha=ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3 ;; \
      *) echo "unsupported architecture '${TARGETARCH}'"; exit 1 ;; \
    esac; \
    get() { curl -fsSL --retry 3 --retry-all-errors --retry-delay 3 -o "$1" "$2"; \
            echo "$3  $1" | sha256sum -c -; }; \
    get /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${TARGETARCH}" "${osv_sha}"; \
    get /tmp/trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${tv_arch}.tar.gz" "${tv_sha}"; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    chmod 0755 /usr/local/bin/osv-scanner /usr/local/bin/trivy; \
    rm -f /tmp/*.tgz

# Each into its own environment under /opt/tools, every file checked against the hash in
# its lock; wheels only, except Barkley itself (see docker/tools/install.py).
ENV UV_PYTHON=/usr/local/bin/python3 \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
COPY docker/tools /src/tools
RUN python3 -I /src/tools/install.py /src/tools /opt/tools

# --- runner ----------------------------------------------------------------------------
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS runner
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/bin/pip* /usr/local/lib/python3.13/site-packages/pip \
      /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
      /usr/local/lib/python3.13/ensurepip/_bundled \
    && install -d -o 10001 -g 10001 /cache /work
COPY --from=tools /usr/local/bin/uv /usr/local/bin/osv-scanner /usr/local/bin/trivy /usr/local/bin/
COPY --from=gitleaks /out/gitleaks /usr/local/bin/
COPY --from=tools /opt/tools /opt/tools
COPY --from=app /opt/scentry /opt/scentry
# HOME and every tool cache live on the /cache volume; the root filesystem is read-only.
ENV PATH=/opt/scentry/bin:/opt/tools/bin:$PATH \
    HOME=/cache \
    XDG_CACHE_HOME=/cache \
    SCENTRY_WORK_DIR=/work \
    SCENTRY_BARKLEY_STORE=/cache/barkley/scans.db \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PYTHON_DOWNLOADS=never \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0
USER 10001:10001
CMD ["scentry", "worker"]
