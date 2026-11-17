"""Get a repository onto disk without running anything from it."""

from __future__ import annotations

import base64
import re
import shutil
from pathlib import Path
from urllib.parse import urlsplit

from scentry import proc
from scentry.config import Settings

_HTTPS = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~/-]+$")
_REF = re.compile(r"^[A-Za-z0-9._/+-]{1,200}$")
_HA_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$")

# Files a repository could use to hide code from a scanner.
IGNORE_FILES = (
    ".semgrepignore", ".gitleaksignore", ".gitleaks.toml", "osv-scanner.toml",
    ".trivyignore", ".trivyignore.yaml", "trivy.yaml", ".bandit", "zizmor.yml",
    ".github/zizmor.yml",
)  # fmt: skip


class AcquireError(Exception):
    pass


def is_local(source: str) -> bool:
    return not source.startswith("https://")


def validate_ref(ref: str | None) -> None:
    if ref and (ref.startswith("-") or ".." in ref or not _REF.match(ref)):
        raise AcquireError("That branch or tag name isn't allowed.")


def validate_source(source: str, settings: Settings) -> None:
    """An https clone URL without credentials in it, or a local path if those are enabled."""
    if is_local(source):
        if not settings.allow_local_paths:
            raise AcquireError("Use an https:// clone URL (local paths are switched off).")
        if not Path(source).is_absolute():
            raise AcquireError("A local path must be absolute.")
        return
    if not _HTTPS.match(source) or urlsplit(source).username is not None:
        raise AcquireError("Use a plain https:// clone URL with no username or token in it.")


def normalize_ha_repo(source: str) -> str:
    """owner/repo from owner/repo or a github.com URL."""
    s = source.strip().removesuffix("/").removesuffix(".git")
    s = re.sub(r"^https://github\.com/", "", s)
    if not _HA_REPO.match(s):
        raise AcquireError("Use owner/repo or a https://github.com/owner/repo URL.")
    return s


def auth_env(url: str, tokens: dict[str, str]) -> dict[str, str]:
    """Git config (via environment, never argv or .git/config) that sends the token for
    this URL's host to that host only."""
    host = (urlsplit(url).hostname or "").lower()
    token = {k.lower(): v for k, v in tokens.items()}.get(host)
    if not token:
        return {}
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": f"http.https://{host}/.extraheader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
    }


def acquire(source: str, ref: str | None, dest: Path, settings: Settings) -> str | None:
    """Clone (or copy) `source` into `dest`; returns the commit sha if there is one."""
    validate_source(source, settings)
    validate_ref(ref)
    if is_local(source):
        if not Path(source).is_dir():
            raise AcquireError("That local path isn't a folder.")
        shutil.copytree(source, dest, symlinks=True)
    else:
        cmd = [
            "git", "-c", "core.symlinks=false", "-c", "core.fsmonitor=false",
            "clone", "--quiet", "--no-recurse-submodules",
        ]  # fmt: skip
        if ref:
            cmd += ["--branch", ref]
        cmd += ["--", source, str(dest)]
        env = {"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
        env.update(auth_env(source, settings.git_tokens))
        try:
            res = proc.run(cmd, timeout=settings.clone_timeout, env=env)
        except Exception as exc:  # timeout, git missing
            raise AcquireError(f"Clone failed: {type(exc).__name__}") from exc
        if res.returncode != 0:
            raise AcquireError(f"Clone failed: {res.stderr.strip()[-400:]}")
    if (dest / ".git").exists():
        head = proc.run(["git", "-C", str(dest), "rev-parse", "HEAD"], timeout=30)
        if head.returncode == 0:
            return head.stdout.strip()
    return None


def remote_head(source: str, ref: str | None, settings: Settings) -> str:
    """The commit `ref` (a branch or tag; the default branch when None) points at now,
    from `git ls-remote`: one request, nothing downloaded, no code. Raises AcquireError."""
    validate_source(source, settings)
    validate_ref(ref)
    if is_local(source):
        raise AcquireError("Local paths aren't watched for commits.")
    wanted = [f"refs/heads/{ref}", f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"] if ref else ["HEAD"]
    env = {"GIT_TERMINAL_PROMPT": "0"}
    env.update(auth_env(source, settings.git_tokens))
    try:
        res = proc.run(["git", "ls-remote", source, *wanted], timeout=60, env=env)
    except Exception as exc:  # timeout, git missing
        raise AcquireError(f"Couldn't ask for new commits: {type(exc).__name__}") from exc
    if res.returncode != 0:
        raise AcquireError(f"Couldn't ask for new commits: {res.stderr.strip()[-300:]}")
    heads = {}
    for line in res.stdout.splitlines():
        sha, _, name = line.partition("\t")
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
            heads[name.strip()] = sha
    # A branch first; for an annotated tag, the commit it points at (the ^{} line).
    for name in (wanted[0], wanted[-1], *wanted[1:-1]) if ref else wanted:
        if name in heads:
            return heads[name]
    raise AcquireError(f"The repository has no {'branch or tag ' + ref if ref else 'HEAD'}.")


def sanitize(tree: Path, settings: Settings) -> list[str]:
    """Remove in-repo scanner ignore/config files; returns what was removed."""
    if settings.honor_repo_ignores:
        return []
    removed = []
    for rel in IGNORE_FILES:
        path = tree / rel
        if path.is_file() or path.is_symlink():
            path.unlink()
            removed.append(rel)
    return removed
