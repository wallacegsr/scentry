from __future__ import annotations

import datetime
import json
import threading

import pytest
from sqlalchemy import select
from websockets.sync.server import serve

from scentry import db, hass, hass_sync, worker
from scentry.config import Settings
from scentry.hass import Connection, HassError, Installed
from scentry.models import CatalogItem, HassSync, Scan, Target, utcnow

TOKEN = "test-token"


def repo(full_name, category="integration", installed="1.0.0", available=None, **extra):
    return {"full_name": full_name, "category": category, "installed": True, "name": full_name,
            "installed_version": installed, "available_version": available or installed,
            **extra}  # fmt: skip


class FakeHA:
    """Speaks Home Assistant's websocket protocol: auth, then id'd commands."""

    def __init__(self, repos, *, marketplace=True, admin=True, subscribe=True):
        self.repos, self.marketplace, self.admin, self.can_subscribe = (
            repos, marketplace, admin, subscribe)  # fmt: skip
        self.received: list[dict] = []
        self.subscriptions: dict[str, int] = {}
        self.conn = None
        self.server = serve(self.handler, "127.0.0.1", 0)
        self.url = f"http://127.0.0.1:{self.server.socket.getsockname()[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()

    def push(self, signal, event):
        self.conn.send(json.dumps({"id": self.subscriptions[signal], "type": "event",
                                   "event": event}))  # fmt: skip

    def handler(self, conn):
        self.conn = conn
        conn.send(json.dumps({"type": "auth_required", "ha_version": "2026.11.2"}))
        auth = json.loads(conn.recv())
        if auth.get("access_token") != TOKEN:
            conn.send(json.dumps({"type": "auth_invalid", "message": "Invalid access token"}))
            return
        conn.send(json.dumps({"type": "auth_ok", "ha_version": "2026.11.2"}))
        for raw in conn:
            msg = json.loads(raw)
            self.received.append(msg)
            mid, kind = msg["id"], msg["type"]

            def ok(result=None, mid=mid):
                conn.send(json.dumps({"id": mid, "type": "result", "success": True,
                                      "result": result}))  # fmt: skip

            def fail(code, mid=mid):
                conn.send(json.dumps({"id": mid, "type": "result", "success": False,
                                      "error": {"code": code, "message": code}}))  # fmt: skip

            known = {"hacs/repositories/list", "marketplace/subscribe"} if not self.marketplace \
                else {"marketplace/repositories/list", "marketplace/subscribe"}
            if not self.can_subscribe:
                known.discard("marketplace/subscribe")
            if kind not in known:
                fail("unknown_command")
            elif not self.admin:
                fail("unauthorized")
            elif kind.endswith("/list"):
                ok(self.repos)
            else:
                self.subscriptions[msg["signal"]] = mid
                ok()


@pytest.fixture
def fake():
    servers = []

    def make(repos, **kw):
        server = FakeHA(repos, **kw)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


@pytest.fixture
def settings(tmp_path):
    return Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'hass.db'}",
                    admin_password="pw")  # fmt: skip


@pytest.fixture
def session(settings):
    db.configure(settings.database_url)
    with db.SessionLocal() as s:
        yield s


# --- parsing and the client -------------------------------------------------------------


def test_parse_installed_validates_everything():
    items, other = hass.parse_installed([
        repo("Good/Integration", installed="v2.0.0", available="v2.1.0"),
        repo("owner/card", category="plugin", installed="a1b2c3d"),
        repo("owner/theme", category="theme"),
        repo("not a repo"),
        repo("owner/evil", installed="--upload-pack=x"),
        repo("owner/odd", available="-x"),
        {"full_name": "owner/not-installed", "category": "integration", "installed": False},
        "junk",
    ])  # fmt: skip
    assert [(i.repo, i.kind, i.installed, i.available) for i in items] == [
        ("Good/Integration", "integration", "v2.0.0", "v2.1.0"),
        ("owner/card", "card", "a1b2c3d", "a1b2c3d"),
        ("owner/odd", "integration", "1.0.0", ""),
    ]
    assert items[0].update and not items[1].update
    assert other == {"theme": 1, "unreadable": 2}
    with pytest.raises(HassError):
        hass.parse_installed({"not": "a list"})


@pytest.mark.parametrize("url", ["ftp://ha:8123", "http://ha:8123/some/path", "ha:8123", ""])
def test_bad_urls(url):
    with pytest.raises(HassError):
        hass.ws_url(url)


def test_ws_url():
    assert hass.ws_url("https://ha.lan:8123/") == "wss://ha.lan:8123/api/websocket"
    assert hass.ws_url("http://192.168.1.10:8123") == "ws://192.168.1.10:8123/api/websocket"


def test_marketplace_list_and_events(fake):
    ha = fake([repo("a/b", available="1.1.0"), repo("c/d", category="theme")])
    conn = Connection(ha.url, TOKEN)
    try:
        assert conn.ha_version == "2026.11.2"
        items, other, source = conn.list_installed()
        assert source == "marketplace/repositories/list"
        assert [i.repo for i in items] == ["a/b"] and other == {"theme": 1}
        assert conn.subscribe() is True
        assert conn.next_event(timeout=0.2) is None
        ha.push(hass.SIGNAL_INSTALL_PROGRESS, {"repository": "a/b", "progress": False})
        signal, data = conn.next_event(timeout=2)
        assert hass.matters(signal, data)
        assert not hass.matters(hass.SIGNAL_REPOSITORY, {"action": "update"})
        assert hass.matters(hass.SIGNAL_REPOSITORY, {"action": "uninstall"})
    finally:
        conn.close()


def test_falls_back_to_hacs_and_polling(fake):
    ha = fake([repo("a/b")], marketplace=False, subscribe=False)
    conn = Connection(ha.url, TOKEN)
    try:
        assert conn.list_installed()[2] == "hacs/repositories/list"
        assert conn.subscribe() is False
    finally:
        conn.close()


def test_refusals(fake):
    ha = fake([], admin=False)
    with pytest.raises(HassError, match="refused the token"):
        Connection(ha.url, "wrong")
    conn = Connection(ha.url, TOKEN)
    try:
        with pytest.raises(HassError, match="administrator"):
            conn.list_installed()
        # Only fixed commands can ever be sent.
        with pytest.raises(HassError, match="not allowed"):
            conn.command("call_service", domain="homeassistant", service="restart")
        assert all(m["type"] != "call_service" for m in ha.received)
    finally:
        conn.close()
    with pytest.raises(HassError, match="can't reach"):
        Connection("http://127.0.0.1:1", TOKEN, timeout=2)


# --- folding the list into targets and the queue -----------------------------------------


def scans_of(session, target):
    return [(s.ref, s.status) for s in session.scalars(
        select(Scan).where(Scan.target_id == target.id).order_by(Scan.id))]  # fmt: skip


def test_apply_lifecycle(session, settings):
    now = utcnow()
    first = [Installed("a/integration", "integration", "A", "1.0.0", "1.1.0"),
             Installed("c/card", "card", "C", "abc1234", "abc1234")]  # fmt: skip
    res = hass_sync.apply(session, first, settings, now)
    assert sorted(res.added) == ["a/integration", "c/card"]
    assert res.queued == [("a/integration", "1.0.0", "installed"),
                          ("a/integration", "1.1.0", "update offered"),
                          ("c/card", "abc1234", "installed")]  # fmt: skip
    a = session.scalar(select(Target).where(Target.source == "a/integration"))
    assert (a.origin, a.hacs_kind, a.ref) == ("hacs", "integration", "1.0.0")
    assert a.update_offered

    # Reading the same list again queues nothing new.
    assert hass_sync.apply(session, first, settings, now).queued == []

    # The update is installed: the new version is already scanned (offered earlier).
    for scan in session.scalars(select(Scan)):
        scan.status, scan.score, scan.verdict, scan.finished_at = "done", 95, "Good Boy", now
    session.commit()
    updated = [Installed("a/integration", "integration", "A", "1.1.0", "1.1.0"), first[1]]
    assert hass_sync.apply(session, updated, settings, now).queued == []
    assert a.ref == "1.1.0" and not a.update_offered

    # Uninstalled: kept, but no longer scheduled. Reinstalled: back on.
    res = hass_sync.apply(session, updated[:1], settings, now)
    card = session.scalar(select(Target).where(Target.source == "c/card"))
    assert res.removed == ["c/card"]
    assert (card.enabled, card.installed_version, card.hacs_removed_at) == (False, None, now)
    assert worker.schedule_due(session, now + datetime.timedelta(days=30)) == 1  # only a/
    hass_sync.apply(session, updated, settings, now)
    assert card.enabled and card.hacs_removed_at is None


def test_apply_adopts_a_manual_target_and_retries_failures(session, settings):
    manual = Target(name="mine", profile="ha", source="Owner/Repo")
    session.add(manual)
    session.commit()
    now = utcnow()
    items = [Installed("owner/repo", "integration", "R", "2.0.0", "")]
    assert hass_sync.apply(session, items, settings, now).added == []
    assert manual.origin == "hacs" and scans_of(session, manual) == [("2.0.0", "queued")]

    scan = session.scalar(select(Scan))
    scan.status, scan.finished_at = "failed", now
    session.commit()
    assert hass_sync.apply(session, items, settings, now).queued == []  # too soon
    later = now + datetime.timedelta(hours=2)
    assert len(hass_sync.apply(session, items, settings, later).queued) == 1
    for s in session.scalars(select(Scan)):
        s.status, s.finished_at = "failed", later
    session.commit()
    much_later = later + datetime.timedelta(hours=2)
    assert len(hass_sync.apply(session, items, settings, much_later).queued) == 1
    for s in session.scalars(select(Scan)):
        s.status, s.finished_at = "failed", much_later
    session.commit()
    # Three failed attempts: it waits for the weekly schedule instead.
    next_day = much_later + datetime.timedelta(days=1)
    assert hass_sync.apply(session, items, settings, next_day).queued == []


def test_sync_once_records_status(session, settings, fake):
    offered = {"full_name": "o/new", "category": "plugin", "installed": False, "name": "New card",
               "description": "Shows things", "available_version": "v3", "stars": 12}
    ha = fake([repo("a/b"), repo("x/theme", category="theme"), offered])
    conn = Connection(ha.url, TOKEN)
    try:
        hass_sync.sync_once(session, conn, settings)
    finally:
        conn.close()
    row = session.get(HassSync, 1)
    assert (row.installed, row.skipped, row.error, row.ha_version) == (
        1, {"theme": 1}, None, "2026.11.2")  # fmt: skip
    assert row.source == "marketplace/repositories/list"
    assert hass_sync.installed_counts(session) == {"integration": 1}
    assert row.catalog_size == 2 and row.catalog_at is not None
    listed = {c.repo: (c.kind, c.installed, c.version, c.stars)
              for c in session.scalars(select(CatalogItem))}  # fmt: skip
    assert listed == {"a/b": ("integration", True, "1.0.0", 0), "o/new": ("card", False, "v3", 12)}


def test_parse_catalog_validates_everything():
    listed = hass.parse_catalog([
        {"full_name": "Good/Card", "category": "plugin", "name": "Good‮Card\n",
         "description": "x" * 900 + "\x1b[31m", "available_version": "v1", "stars": 5,
         "downloads": True},
        {"full_name": "o/no-version", "category": "integration", "available_version": "-x",
         "stars": -3, "downloads": 40},
        {"full_name": "not a repo", "category": "integration"},
        {"full_name": "o/theme", "category": "theme"},
        "junk",
    ])  # fmt: skip
    good, plain = listed
    assert (good.repo, good.kind, good.name, good.version) == (
        "Good/Card", "card", "Good Card", "v1")  # fmt: skip
    assert len(good.description) == 500 and "\x1b" not in good.description
    assert good.downloads is None and good.stars == 5
    assert (plain.version, plain.stars, plain.downloads, plain.name) == ("", 0, 40, "o/no-version")
    with pytest.raises(HassError):
        hass.parse_catalog({"not": "a list"})


def test_store_catalog_follows_the_marketplace(session):
    now = utcnow()
    first = hass.parse_catalog([
        {"full_name": f"o/{n}", "category": "integration", "available_version": "1"}
        for n in ("a", "b")])  # fmt: skip
    hass_sync.store_catalog(session, first, now)
    session.commit()
    later = now + datetime.timedelta(minutes=10)
    second = hass.parse_catalog([
        {"full_name": "o/a", "category": "integration", "available_version": "2"},
        {"full_name": "o/c", "category": "plugin"}])  # fmt: skip
    hass_sync.store_catalog(session, second, later)
    session.commit()
    rows = {c.repo: (c.version, c.seen_at) for c in session.scalars(select(CatalogItem))}
    assert rows == {"o/a": ("2", later), "o/c": (None, later)}


def test_enqueue_keeps_two_versions_apart(session):
    target = Target(name="t", profile="ha", source="a/b")
    session.add(target)
    session.commit()
    one = worker.enqueue(session, target, "1.0.0")
    two = worker.enqueue(session, target, "1.1.0")
    assert one.id != two.id
    assert worker.enqueue(session, target, "1.0.0").id == one.id
