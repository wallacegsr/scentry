#!/bin/sh
# Locks the scanners' Python dependencies: docker/tools/<name>/uv.lock, from the version
# pinned in docker/tools/<name>/pyproject.toml. Runs uv on Linux, as the runner image
# does, with the Python each one's requires-python pins (3.13; 3.14 for Barkley). After
# changing a version:
#   docker/tools/lock.sh            every scanner
#   docker/tools/lock.sh semgrep    one
#   docker/tools/lock.sh --check    fail if a lock is out of date (CI runs this)
set -eu
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1  # Git Bash on Windows: leave the container paths alone

check=""
if [ "${1:-}" = "--check" ]; then check="--check"; shift; fi
tools="${*:-$(cd docker/tools && ls -d */ | tr -d /)}"

docker build -q --target uv -t scentry-uv -f docker/Dockerfile . >/dev/null
here=$(pwd -W 2>/dev/null || pwd)
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e UV_NO_CACHE=1 \
    -e UV_PYTHON_DOWNLOADS=never \
    -v "$here/docker/tools:/tools" -w /tools scentry-uv \
    sh -euc '
      for t in "$@"; do
        py=$(sed -n "s/^requires-python = \"==\(3\.[0-9]*\)\.\*\"\$/\1/p" "$t/pyproject.toml")
        echo "== $t (Python $py)"
        uv lock $0 --project "$t" --python "/usr/local/bin/python$py"
      done' "$check" $tools
