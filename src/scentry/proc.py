"""Run a scanner binary with a scrubbed environment: no tokens, no database URL."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
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


def keep_secrets_from_children() -> bool:
    """Make this process non-dumpable (Linux): a scanner runs as the same user, and could
    otherwise read this process's environment (the git tokens, the database password)
    from /proc/<pid>/environ, or its memory. The scanners themselves are unaffected:
    starting a program makes it dumpable again. Returns whether it worked."""
    if not sys.platform.startswith("linux"):
        return False
    pr_set_dumpable = 4
    try:
        return ctypes.CDLL(None, use_errno=True).prctl(pr_set_dumpable, 0, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


_TEMP: ContextVar[Path | None] = ContextVar("scentry_temp", default=None)


@contextmanager
def temp_dir(path: Path) -> Iterator[None]:
    """Programs started within this keep their temporary files in `path` instead of the
    system's /tmp. A scan's then count against its work folder's size (which has room
    for them; /tmp is small) and are removed with it."""
    token = _TEMP.set(path)
    try:
        yield
    finally:
        _TEMP.reset(token)


def clean_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in _PASS or k.startswith(_PASS_PREFIX)}
    if (temp := _TEMP.get()) is not None:
        env.update(TMPDIR=str(temp), TEMP=str(temp), TMP=str(temp))
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
