"""The admin's password: changed in the portal, reset with `scentry reset-password`."""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from scentry import db, passwords
from scentry.config import Settings
from scentry.models import AdminPassword, LogEntry
from scentry.web.app import SignInLimit, create_app

OLD = ("admin", "pw")
NEW = "correct horse battery staple"


@pytest.fixture(autouse=True)
def quick(monkeypatch):
    """Cheap hashes for the tests; the real settings are checked on their own."""
    monkeypatch.setattr(passwords, "N", 2**10)
    monkeypatch.setattr(passwords, "P", 1)


def settings_for(tmp_path, **kw):
    return Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'pw.db'}",
                    **{"admin_password": "pw", **kw})  # fmt: skip


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(settings_for(tmp_path)), follow_redirects=False)


def stored():
    with db.SessionLocal() as s:
        return s.get(AdminPassword, 1)


def test_hashes(monkeypatch):
    monkeypatch.undo()  # the real settings
    made = passwords.hash_password(NEW)
    assert made.startswith("scrypt$32768$8$3$") and len(made) < 300
    assert made != passwords.hash_password(NEW)  # a salt of its own each time
    assert passwords.check_password(NEW, made) and not passwords.check_password("pw", made)
    for broken in ("", "scrypt", "bcrypt$1$2$3$4$5", "scrypt$1$8$1$!!$??", "scrypt$x$8$1$AA$AA"):
        assert not passwords.check_password(NEW, broken)


def test_what_a_new_password_needs():
    assert passwords.problem(NEW, NEW) is None
    assert "aren't the same" in passwords.problem(NEW, NEW + "!")
    assert "at least 12" in passwords.problem("short", "short")
    assert "at most" in passwords.problem("x" * 1025, "x" * 1025)
    assert "only spaces" in passwords.problem(" " * 12, " " * 12)


def test_a_matched_password_is_remembered(monkeypatch):
    first, second = passwords.hash_password(NEW), passwords.hash_password(NEW)
    calls = []
    real = passwords.check_password
    monkeypatch.setattr(passwords, "check_password", lambda p, h: calls.append(h) or real(p, h))
    seen = passwords.Verified()
    assert seen.check(NEW, first) and seen.check(NEW, first) and calls == [first]
    assert not seen.check("wrong", first) and len(calls) == 2  # a wrong one is always hashed
    assert seen.check(NEW, second) and calls[-1] == second  # a new hash: checked again


def test_change_the_password_in_the_portal(client, caplog):
    page = client.get("/system", auth=OLD).text
    assert "SCENTRY_ADMIN_PASSWORD, from .env." in page
    assert '<a href="/system/password">Change the password</a>' in page
    form = client.get("/system/password", auth=OLD).text
    assert 'name="current" type="password" autocomplete="current-password"' in form
    assert 'autocomplete="username" hidden>' in form and 'name="username"' not in form

    good = {"current": "pw", "new": NEW, "repeat": NEW}
    for change, says in (({"current": "nope"}, "That isn&#39;t the current password."),
                         ({"new": "pw", "repeat": "pw"}, "That&#39;s the password already."),
                         ({"repeat": NEW + "!"}, "aren&#39;t the same"),
                         ({"new": "too short", "repeat": "too short"}, "at least 12")):
        r = client.post("/system/password", data={**good, **change}, auth=OLD)
        assert r.status_code == 400 and says in r.text
        assert NEW not in r.text and "nope" not in r.text  # nothing typed comes back
    cross = client.post("/system/password", data=good, auth=OLD,
                        headers={"Sec-Fetch-Site": "cross-site"})  # fmt: skip
    assert cross.status_code == 403 and stored() is None

    with caplog.at_level(logging.INFO, logger="scentry"):
        r = client.post("/system/password", data=good, auth=OLD)
    assert r.status_code == 303 and r.headers["location"] == "/system?password=changed"
    assert "changed in the portal, signed in as admin" in caplog.text and NEW not in caplog.text
    row = stored()
    assert row.set_by == "portal" and row.hash.startswith("scrypt$") and NEW not in row.hash

    # The old password, from .env, signs in no more: the browser asks for the new one.
    old = client.get("/system?password=changed", auth=OLD)
    assert old.status_code == 401 and old.headers["www-authenticate"].startswith("Basic")
    page = client.get("/system?password=changed", auth=("admin", NEW)).text
    assert "The password is changed." in page and "changed in the portal" in page
    assert "SCENTRY_ADMIN_PASSWORD in .env no longer signs in" in page


def test_a_wrong_current_password_counts_as_a_wrong_sign_in(client, monkeypatch):
    monkeypatch.setattr(SignInLimit, "LIMIT", 3)
    for _ in range(3):
        r = client.post("/system/password", data={"current": "guess", "new": NEW, "repeat": NEW},
                        auth=OLD)  # fmt: skip
        assert r.status_code == 400
    assert client.get("/system", auth=OLD).status_code == 429  # that address waits now


def test_with_no_password_in_env_once_one_is_set(tmp_path):
    with pytest.raises(RuntimeError, match="SCENTRY_ADMIN_PASSWORD"):
        create_app(settings_for(tmp_path, admin_password=""))
    with db.SessionLocal() as s:
        passwords.set_password(s, NEW, "command")
        s.commit()
    client = TestClient(create_app(settings_for(tmp_path, admin_password="")))
    assert client.get("/", auth=("admin", NEW)).status_code == 200
    assert client.get("/", auth=("admin", "")).status_code == 401


def test_only_for_signing_in_with_a_password(tmp_path):
    client = TestClient(create_app(settings_for(tmp_path, auth_mode="none")),
                        follow_redirects=False)  # fmt: skip
    assert "No sign-in (SCENTRY_AUTH_MODE=none)" in client.get("/system").text
    assert client.get("/system/password").status_code == 404
    assert client.post("/system/password", data={"current": "pw", "new": NEW,
                                                  "repeat": NEW}).status_code == 404


def test_reset_password_command(tmp_path):
    settings = settings_for(tmp_path)
    said = []
    answers = iter([NEW, NEW + "!", "short", "short", NEW, NEW])

    def run(**kw):
        said.clear()
        return passwords.reset(settings, ask=lambda _: next(answers), say=said.append, **kw)

    assert run() == 1 and "aren't the same" in said[0] and stored() is None
    assert run() == 1 and "at least 12" in said[0]
    assert run() == 0 and "reset with scentry reset-password" in said[-1]
    assert stored().set_by == "command" and passwords.check_password(NEW, stored().hash)
    client = TestClient(create_app(settings))
    assert client.get("/", auth=("admin", NEW)).status_code == 200

    assert run(generate=True) == 0 and said[0].startswith("The new password, shown this once: ")
    made = said[0].rsplit(" ", 1)[1]
    assert len(made) == 24 and passwords.check_password(made, stored().hash)
    assert client.get("/", auth=("admin", NEW)).status_code == 401
    assert client.get("/", auth=("admin", made)).status_code == 200

    assert run(use_env=True) == 0 and stored() is None
    assert client.get("/", auth=OLD).status_code == 200  # .env's again
    assert run(use_env=True) == 0 and "already signs in" in said[0]
    assert passwords.reset(settings_for(tmp_path, admin_password=""), use_env=True,
                           say=said.append) == 1  # nothing would sign in  # fmt: skip

    def no_terminal(_):
        raise EOFError

    assert passwords.reset(settings, ask=no_terminal, say=said.append) == 1
    assert "docker exec -it" in said[-1]
    with db.SessionLocal() as s:
        logged = [e.message for e in s.query(LogEntry).order_by(LogEntry.id)]
    assert logged == ["The admin password was reset with scentry reset-password."] * 2 + [
        "The admin password was set back to SCENTRY_ADMIN_PASSWORD."]
    assert not any(NEW in m or made in m for m in logged)
