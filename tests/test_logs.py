"""The services' log in the database (logs.py) and the portal's Log page."""

from __future__ import annotations

import datetime
import logging
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scentry import db, logs
from scentry.config import Settings
from scentry.models import LogEntry, utcnow
from scentry.web.app import create_app

AUTH = ("admin", "pw-for-the-portal")


@pytest.fixture
def settings(tmp_path):
    s = Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'log.db'}",
                 admin_password="pw-for-the-portal")  # fmt: skip
    db.configure(s.database_url)
    return s


@pytest.fixture
def handler(settings):
    """A handler as a service installs it, on a logger of its own (not the root's)."""
    h = logs.DatabaseHandler("runner", ["sekrit-token-1234"])
    yield h
    h.close()


def _log(handler, name, level, msg, *args, exc_info=None):
    record = logging.getLogger(name).makeRecord(name, level, "x.py", 1, msg, args, exc_info)
    handler.handle(record)


def _entries():
    with db.SessionLocal() as s:
        return s.scalars(select(LogEntry).order_by(LogEntry.id)).all()


def test_keeps_what_is_worth_keeping(handler):
    _log(handler, "scentry.pipeline", logging.INFO, "scan %s: %s", 7, "barkley")
    _log(handler, "scentry.pipeline", logging.DEBUG, "too chatty")
    _log(handler, "httpx", logging.INFO, "HTTP Request: GET https://example.org")  # a library
    _log(handler, "apprise", logging.WARNING, "Failed to send to sekrit-token-1234")
    _log(handler, "uvicorn.access", logging.WARNING, "GET / 404")
    _log(handler, "sqlalchemy.engine", logging.ERROR, "about writing the log itself")
    try:
        raise ValueError("boom")
    except ValueError:
        _log(handler, "scentry.worker", logging.ERROR, "pass failed", exc_info=sys.exc_info())
    handler.flush()

    got = [(e.service, e.level, e.logger, e.message.splitlines()[0]) for e in _entries()]
    assert got == [
        ("runner", logging.INFO, "scentry.pipeline", "scan 7: barkley"),
        ("runner", logging.WARNING, "apprise", "Failed to send to [redacted]"),
        ("runner", logging.ERROR, "scentry.worker", "pass failed"),
    ]
    assert "ValueError: boom" in _entries()[-1].message  # the traceback is kept
    assert abs((_entries()[0].at - utcnow()).total_seconds()) < 60  # naive UTC


def test_a_long_message_keeps_its_start_and_end(handler):
    _log(handler, "scentry.x", logging.ERROR, "start " + "x" * 20_000 + " end")
    handler.flush()
    (e,) = _entries()
    assert len(e.message) <= logs.MESSAGE_MAX + 3
    assert e.message.startswith("start ") and e.message.endswith(" end") and "\n…\n" in e.message


def test_a_database_that_cant_take_it_doesnt_stop_the_service(handler, capsys, monkeypatch):
    def broken():
        raise RuntimeError("database is down")

    monkeypatch.setattr(db, "SessionLocal", broken)
    for message in ("one", "two"):  # two writes that fail: said once
        _log(handler, "scentry.x", logging.WARNING, message)
        handler.flush()
    err = capsys.readouterr().err
    assert err.count("The log can't be kept in the database for now: RuntimeError") == 1


def test_secrets_of_each_service(settings):
    s = Settings(_env_file=None, database_url="postgresql+psycopg://scentry:db-pass-123@db/x",
                 git_tokens={"github.com": "ghp_abcdefgh"}, hass_token="hass-long-lived",
                 notify_urls="tgram://123456:bot-token-xyz/987654, ntfy://ntfy.sh/my-secret-topic",
                 admin_password="short")  # fmt: skip
    found = logs.secrets_of(s)
    for secret in ("db-pass-123", "ghp_abcdefgh", "hass-long-lived", "bot-token-xyz",
                   "my-secret-topic", "tgram://123456:bot-token-xyz/987654"):
        assert secret in found
    assert "short" not in found and "tgram" not in found  # too short to blank safely
    assert found == sorted(found, key=len, reverse=True)  # a whole URL before its parts
    text = logs.redact("sent to tgram://123456:bot-token-xyz/987654", found)
    assert text == "sent to [redacted]"


def test_prune(settings):
    now = utcnow()
    with db.SessionLocal() as s:
        for days in (30, 15, 13, 0):
            s.add(LogEntry(at=now - datetime.timedelta(days=days), service="web", level=20,
                           logger="scentry", message=f"{days} days old"))  # fmt: skip
        s.commit()
        logs.prune(s, 14, now)
        s.commit()
        assert [e.message for e in s.scalars(select(LogEntry))] == ["13 days old", "0 days old"]


def test_prune_keeps_the_newest_rows(settings, monkeypatch):
    monkeypatch.setattr(logs, "KEEP_ROWS", 3)
    with db.SessionLocal() as s:
        for i in range(5):
            s.add(LogEntry(at=utcnow(), service="web", level=20, logger="scentry", message=str(i)))
        s.commit()
        logs.prune(s, 14, utcnow())
        s.commit()
        assert [e.message for e in s.scalars(select(LogEntry))] == ["2", "3", "4"]


def test_the_web_service_prunes(settings):
    with db.SessionLocal() as s:
        s.add(LogEntry(at=utcnow() - datetime.timedelta(days=99), service="web", level=20,
                       logger="scentry", message="old"))  # fmt: skip
        s.commit()
    h = logs.install("web", settings, prune_old=True)
    try:
        logging.getLogger("scentry.test").info("new")
        h.flush()
        assert [e.message for e in _entries()] == ["new"]
        assert logging.getLogger("scentry").getEffectiveLevel() <= logging.INFO
    finally:
        logging.getLogger().removeHandler(h)
        h.close()


def _add(**kw):
    with db.SessionLocal() as s:
        s.add(LogEntry(**{"at": utcnow(), "service": "runner", "level": logging.INFO,
                          "logger": "scentry.pipeline", **kw}))  # fmt: skip
        s.commit()


def test_log_page(settings):
    client = TestClient(create_app(settings))
    assert client.get("/log").status_code == 401
    assert "Nothing logged yet." in client.get("/log", auth=AUTH).text
    _add(message="scan 12 (Agent): barkley ok: sniff-test; didn't finish: guarddog (<b>x</b>)",
         level=logging.WARNING)
    _add(message="scan 13: barkley", service="runner")
    _add(message="couldn't send\nTraceback (most recent call last):\n  boom", service="notify",
         level=logging.ERROR, logger="scentry.notify")

    page = client.get("/log", auth=AUTH).text
    newest_first = ("couldn&#39;t send", 'href="/scans/13"', 'href="/scans/12"')
    assert [page.index(t) for t in newest_first] == sorted(page.index(t) for t in newest_first)
    assert '<a href="/scans/12">scan 12</a> (Agent)' in page
    assert "<b>x</b>" not in page and "(&lt;b&gt;x&lt;/b&gt;)" in page  # escaped
    assert "<summary>2 more lines</summary>" in page and "  boom</pre>" in page
    assert '<span class="pill bad">error</span>' in page
    assert '<span class="pill warn">warning</span>' in page

    def shown(**params):
        text = client.get("/log", params=params, auth=AUTH).text
        found = [n for n in (12, 13) if f"scan {n}</a>" in text]
        return found + ["send"] * ("couldn&#39;t send" in text)

    assert shown(level="warning") == [12, "send"]
    assert shown(level="error") == ["send"]
    assert shown(service="notify") == ["send"]
    assert shown(q="GUARDDOG barkley") == [12]
    assert shown(q="scentry.notify") == ["send"]  # the logger's name counts too
    assert shown(q="100%") == [] and shown(q="_") == []  # LIKE's wildcards are only text
    assert shown(service="nonsense", level="nonsense") == [12, 13, "send"]

    system = client.get("/system", auth=AUTH).text
    assert "Last 24 hours: 1 error, 1 warning." in system
    assert '<a href="/log?level=warning">' in system


def test_log_page_goes_back_in_time(settings, monkeypatch):
    monkeypatch.setattr("scentry.web.app.LOG_PAGE", 2)
    for i in range(5):
        _add(message=f"message {i}", service="ai")
    client = TestClient(create_app(settings))
    first = client.get("/log", params={"service": "ai"}, auth=AUTH).text
    assert "message 4" in first and "message 3" in first and "message 2" not in first
    assert "« Newest" not in first and 'href="?service=ai&amp;before=4#log">Older' in first
    second = client.get("/log", params={"service": "ai", "before": 4}, auth=AUTH).text
    assert "message 2" in second and "message 1" in second and "message 3" not in second
    assert 'href="?service=ai#log">« Newest' in second
    last = client.get("/log", params={"service": "ai", "before": 2}, auth=AUTH).text
    assert "message 0" in last and "Older" not in last
