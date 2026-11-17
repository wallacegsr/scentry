"""Run a scanner binary with a scrubbed environment: no tokens, no database URL."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

_PASS = {
    "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "USERPROFILE",
    "XDG_CACHE_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
}  # fmt: skip
_PASS_PREFIX = ("SEMGREP_", "UV_", "TRIVY_", "SNIFF_TEST_")


@dataclass(slots=True)
class Result:
    returncode: int
    stdout: str
    stderr: str


def clean_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in _PASS or k.startswith(_PASS_PREFIX)}
    env.update(extra or {})
    return env


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int,
    env: dict[str, str] | None = None,
) -> Result:
    """Raises subprocess.TimeoutExpired (the child is killed) or OSError."""
    done = subprocess.run(
        cmd,
        cwd=cwd,
        env=clean_env(env),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    return Result(done.returncode, done.stdout, done.stderr)
