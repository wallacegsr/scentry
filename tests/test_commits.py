"""Scanning my code on new commits: git ls-remote, then a scan when the head moved."""

from __future__ import annotations

import datetime
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scentry import acquire, commits, db
from scentry.config import Settings
from scentry.models import Scan, Target, utcnow
from scentry.proc import Result

A, B = "a" * 40, "b" * 40
MINUTE = datetime.timedelta(minutes=1)


@pytest.fixture
def settings(tmp_path):
    return Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'c.db'}",
                    admin_password="pw", git_tokens={"git.example": "tok"})  # fmt: skip


@pytest.fixture
def session(settings):
    db.configure(settings.database_url)
    with db.SessionLocal() as s:
        yield s


@pytest.fixture
def remote(monkeypatch):
    """git ls-remote, faked: answers from `heads`, records what it was asked."""
    state = {"heads": {"HEAD": A}, "calls": [], "fail": None}

    def fake(cmd, **kw):
        state["calls"].append((cmd, kw.get("env")))
        if state["fail"]:
            return Result(128, "", state["fail"])
        out = "".join(f"{sha}\t{name}\n" for name, sha in state["heads"].items()
                      if name in cmd[3:])  # fmt: skip
        return Result(0, out, "")

    monkeypatch.setattr("scentry.acquire.proc.run", fake)
    return state


def mine(session, **kw):
    t = Target(name="app", profile="owned", source="https://git.example/me/app.git", **kw)
    session.add(t)
    session.commit()
    return t


def done(session, target, sha):
    session.add(Scan(target_id=target.id, status="done", commit_sha=sha, finished_at=utcnow()))
    session.commit()


def test_remote_head(settings, remote, tmp_path):
    assert acquire.remote_head("https://git.example/me/app.git", None, settings) == A
    cmd, env = remote["calls"][-1]
    assert cmd == ["git", "ls-remote", "https://git.example/me/app.git", "HEAD"]
    assert "tok" not in " ".join(cmd) and "GIT_CONFIG_VALUE_0" in env  # token in env only

    remote["heads"] = {"refs/heads/main": B, "refs/tags/main": A}
    assert acquire.remote_head("https://git.example/me/app.git", "main", settings) == B
    # An annotated tag: the commit it points at.
    remote["heads"] = {"refs/tags/v1": "c" * 40, "refs/tags/v1^{}": A}
    assert acquire.remote_head("https://git.example/me/app.git", "v1", settings) == A

    with pytest.raises(acquire.AcquireError, match="no branch or tag nope"):
        acquire.remote_head("https://git.example/me/app.git", "nope", settings)
    for bad_ref in ("--upload-pack=x", "a..b"):
        with pytest.raises(acquire.AcquireError):
            acquire.remote_head("https://git.example/me/app.git", bad_ref, settings)
    with pytest.raises(acquire.AcquireError, match="Local paths"):
        acquire.remote_head(str(tmp_path), None, settings.model_copy(
            update={"allow_local_paths": True}))  # fmt: skip
    remote["fail"] = "fatal: repository not found"
    with pytest.raises(acquire.AcquireError, match="repository not found"):
        acquire.remote_head("https://git.example/me/app.git", None, settings)


def test_a_new_commit_is_scanned(session, settings, remote):
    t = mine(session)
    done(session, t, A)
    now = utcnow()
    assert commits.check_due(session, settings, now) is True
    assert t.head_sha == A and session.scalar(select(Scan).where(Scan.status == "queued")) is None
    assert commits.check_due(session, settings, now + 5 * MINUTE) is False  # not yet

    remote["heads"]["HEAD"] = B  # pushed
    later = now + 16 * MINUTE
    assert commits.check_due(session, settings, later) is True
    queued = session.scalar(select(Scan).where(Scan.status == "queued"))
    assert queued is not None and t.head_sha == B
    # While that scan waits, the target isn't asked again.
    assert commits.due(session, settings, later + 30 * MINUTE) is None

    queued.status, queued.commit_sha = "done", B
    session.commit()
    assert commits.check_due(session, settings, later + 32 * MINUTE)
    assert session.scalar(select(Scan).where(Scan.status == "queued")) is None


def test_errors_are_shown_and_retried_later(session, settings, remote):
    t = mine(session)
    remote["fail"] = "fatal: could not read Username"
    now = utcnow()
    commits.check_due(session, settings, now)
    assert "could not read Username" in t.head_error
    remote["fail"] = None
    commits.check_due(session, settings, now + 16 * MINUTE)
    assert t.head_error is None and t.head_sha == A


def test_which_targets_are_watched(session, settings, remote):
    mine(session, watch_commits=False)
    mine(session, enabled=False)
    session.add_all([Target(name="local", profile="owned", source="/srv/app"),
                     Target(name="ha", profile="ha", source="o/r")])  # fmt: skip
    session.commit()
    assert commits.due(session, settings, utcnow()) is None
    watched = mine(session)
    assert commits.due(session, settings, utcnow()).id == watched.id
    never = settings.model_copy(update={"commit_poll_minutes": 0})
    assert commits.due(session, never, utcnow()) is None


def test_the_portal_switch(tmp_path):
    from scentry.web.app import create_app

    s = Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'w.db'}",
                 admin_password="pw")  # fmt: skip
    client = TestClient(create_app(s), follow_redirects=False)
    auth = ("admin", "pw")
    client.post("/targets", auth=auth, data={"profile": "owned",
                                             "source": "https://git.example/me/app.git"})
    page = client.get("/targets/1", auth=auth).text
    assert "Each new commit on the default branch is scanned" in page
    assert client.post("/targets/1/watch", auth=auth, data={"on": "off"}).status_code == 303
    assert "New commits aren't scanned" in client.get("/targets/1", auth=auth).text
    with db.SessionLocal() as session:
        assert session.get(Target, 1).watch_commits is False
    assert client.post("/targets/1/watch", auth=auth, data={"on": "maybe"}).status_code == 400


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_remote_head_against_a_real_repository(tmp_path, monkeypatch):
    """ls-remote's real output, parsed (a file:// remote stands in for https)."""
    repo = tmp_path / "r"
    repo.mkdir()

    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()  # fmt: skip

    git("init", "-q", "-b", "main")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x")
    git("-c", "user.name=t", "-c", "user.email=t@t", "tag", "-a", "v1", "-m", "v1")
    head = git("rev-parse", "HEAD")
    url = repo.resolve().as_uri()
    monkeypatch.setattr(acquire, "validate_source", lambda source, settings: None)
    monkeypatch.setattr(acquire, "is_local", lambda source: False)
    s = Settings(_env_file=None)
    assert acquire.remote_head(url, None, s) == head
    assert acquire.remote_head(url, "main", s) == head
    assert acquire.remote_head(url, "v1", s) == head  # the tag object peeled
