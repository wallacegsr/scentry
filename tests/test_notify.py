from __future__ import annotations

import datetime
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from sqlalchemy import select

from scentry import db, findings, notify
from scentry.config import Settings
from scentry.models import Finding, HassSync, NotifyState, Scan, Target, utcnow
from scentry.scanners.base import RawFinding, ScannerRun

NOW = utcnow()
MIN = datetime.timedelta(minutes=1)


@pytest.fixture
def settings(tmp_path):
    return Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'n.db'}",
                    admin_password="pw", public_url="https://scentry.lan/")  # fmt: skip


@pytest.fixture
def session(settings):
    db.configure(settings.database_url)
    with db.SessionLocal() as s:
        yield s


class Receiver:
    """A notification service: records what Apprise's json:// posts to it."""

    def __init__(self, status=200):
        self.posts: list[dict] = []
        self.status = status
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.posts.append({"path": self.path, **json.loads(body)})
                self.send_response(outer.status)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def receiver():
    made = []

    def make(**kw):
        r = Receiver(**kw)
        made.append(r)
        return r

    yield make
    for r in made:
        r.server.shutdown()


def ha_target(session, **kw):
    fields = {"name": "Auto Backup", "profile": "ha", "source": "jc/auto-backup",
              "origin": "hacs", "hacs_kind": "integration", "installed_version": "1.0.0",
              "available_version": "1.0.0", "ref": "1.0.0", **kw}  # fmt: skip
    t = Target(**fields)
    session.add(t)
    session.commit()
    return t


def scan(session, target, ref, score=None, *, status="done", at=NOW, report=None, error=None):
    verdict = None if score is None else (
        "Good Boy" if score >= 90 else "Kinda Sus" if score >= 70 else
        "Very Sus" if score >= 40 else "BORK BORK BORK")  # fmt: skip
    s = Scan(target_id=target.id, ref=ref, status=status, score=score, verdict=verdict,
             finished_at=at, complete=True, report=report, error=error)  # fmt: skip
    session.add(s)
    session.commit()
    return s


# --- deciding -------------------------------------------------------------------------------


def test_safe_strips_what_could_ride_into_a_message():
    hostile = "@everyone [click](https://evil.example) <b>x</b>\x1b[31m `rm` **bold**"
    out = notify.safe(hostile)
    for bad in ("@", "[", "]", "://", "<", ">", "\x1b", "`", "*"):
        assert bad not in out
    assert notify.safe("custom_components/x/__init__.py") == "custom_components/x/__init__.py"
    assert len(notify.safe("a" * 500, 50)) == 50


def test_installed_version_announced_once(session, settings):
    t = ha_target(session)
    report = {"findings": [
        {"severity": "critical", "title": "Runs <code> from @someone", "file": "x/__init__.py",
         "line": 3},
        {"severity": "low", "title": "minor"}]}  # fmt: skip
    first = scan(session, t, "1.0.0", 30, report=report)
    item = notify.evaluate(session, first, settings)
    assert item.level == "failure" and item.head == "Installed in Home Assistant"
    assert "Auto Backup (jc/auto-backup) 1.0.0 scores 30, BORK BORK BORK" in item.text
    assert item.lines == ["critical: Runs code from someone (barkley) in x/__init__.py:3"]

    # The weekly rescan says the same: quiet. Ten points worse: said again.
    assert notify.evaluate(session, scan(session, t, "1.0.0", 32), settings) is None
    worse = notify.evaluate(session, scan(session, t, "1.0.0", 20), settings)
    assert "(was 32, BORK BORK BORK)" in worse.text
    # A fine one is never announced.
    assert notify.evaluate(session, scan(session, t, "1.0.0", 95), settings) is None


def test_offered_update(session, settings):
    t = ha_target(session, available_version="1.1.0")
    scan(session, t, "1.0.0", 95)
    worse = notify.evaluate(session, scan(session, t, "1.1.0", 80), settings)
    assert worse.level == "warning" and "installed 1.0.0 scored 95, Good Boy" in worse.text
    assert worse.head == "Update offered: look before installing"
    fine = scan(session, t, "1.1.0", 93)
    assert notify.evaluate(session, fine, settings) is None
    settings.notify_clean_updates = True
    item = notify.evaluate(session, fine, settings)
    assert item.level == "info" and item.head == "Update offered: looks fine"


def test_my_code_new_findings_only(session, settings):
    t = Target(name="my-app", profile="owned", source="https://github.com/me/app.git")
    session.add(t)
    session.commit()

    def run(*raws):
        s = scan(session, t, None, 0)
        findings.reconcile(session, t, s, [ScannerRun("semgrep", "ok", findings=list(raws))])
        s.score, s.verdict = findings.grade(
            session.scalars(select(Finding).where(Finding.status == "open")).all(), True)
        session.commit()
        return s

    crit = RawFinding("semgrep", "r1", "eval of input", "critical", file="app.py", line=4)
    low = RawFinding("semgrep", "r2", "style", "low", file="b.py")
    item = notify.evaluate(session, run(crit, low), settings)
    assert item.level == "failure"
    assert item.text == "my-app: 1 new finding (1 critical); now grade D (69)"
    assert item.lines == ["critical: eval of input (semgrep) in app.py:4"]
    assert notify.evaluate(session, run(crit, low), settings) is None  # nothing new
    assert notify.evaluate(session, run(low), settings) is None  # fixed
    assert "1 new finding" in notify.evaluate(session, run(crit, low), settings).text  # back


def test_failures_announced_when_they_start(session, settings):
    t = ha_target(session)
    one = scan(session, t, "1.0.0", status="failed", error="clone failed: <@here>")
    item = notify.evaluate(session, one, settings)
    assert item.head == "Scan failed" and item.lines == ["clone failed here"]
    assert notify.evaluate(session, scan(session, t, "1.0.0", status="failed"), settings) is None
    settings.notify_failures = False
    assert notify.evaluate(session, one, settings) is None


def test_a_target_overrides_the_defaults(session, settings):
    t = ha_target(session)
    kinda = scan(session, t, "1.0.0", 75)  # Kinda Sus: under 70 is the default threshold
    assert notify.evaluate(session, kinda, settings) is None
    t.notify_score_below = 90  # this one I want to hear about sooner
    assert "scores 75, Kinda Sus" in notify.evaluate(session, kinda, settings).text
    t.notify_muted = True  # ... or not at all
    assert notify.evaluate(session, kinda, settings) is None
    assert notify.evaluate(session, scan(session, t, "1.0.0", 10), settings) is None
    t.notify_muted = False
    t.notify_failures = False
    assert notify.evaluate(session, scan(session, t, "1.0.0", status="failed"), settings) is None

    # Every offered update of this one, though the default is only the bad ones.
    up = ha_target(session, name="Weather", source="a/weather", available_version="2.0.0")
    scan(session, up, "1.0.0", 95)
    fine = scan(session, up, "2.0.0", 94)
    assert notify.evaluate(session, fine, settings) is None
    up.notify_clean_updates = True
    assert notify.evaluate(session, fine, settings).head == "Update offered: looks fine"


def test_my_code_threshold_per_target(session, settings):
    t = Target(name="lib", profile="owned", source="https://github.com/me/lib.git")
    session.add(t)
    session.commit()
    s = scan(session, t, None, 97)
    findings.reconcile(session, t, s, [ScannerRun("semgrep", "ok", findings=[
        RawFinding("semgrep", "r", "weak hash", "medium", file="h.py")])])  # fmt: skip
    session.commit()
    assert notify.evaluate(session, s, settings) is None  # default: high and worse
    t.notify_min_severity = "medium"
    assert notify.evaluate(session, s, settings).lines == ["medium: weak hash (semgrep) in h.py"]


def test_rules_record_the_defaults_for_the_portal(settings):
    settings.notify_score_below = 90
    assert notify.Rules.defaults(settings).as_dict() == {
        "score_below": 90, "min_severity": "high", "clean_updates": False, "failures": True}


def test_collect_marks_quiet_and_stale_and_waits_for_busy_targets(session, settings):
    t = ha_target(session)
    old = scan(session, t, "1.0.0", 20, at=NOW - datetime.timedelta(days=2))
    fine = scan(session, t, "1.0.0", 95)
    bad = scan(session, t, "1.0.0", 20)
    busy = scan(session, t, "1.1.0", status="queued", at=None)
    assert notify.collect(session, settings, NOW) == []  # its target still has a scan to run
    assert old.notice == "stale" and fine.notice is None
    busy.status = "done"
    busy.score, busy.finished_at = 99, NOW
    items = notify.collect(session, settings, NOW)
    assert [i.scan_id for i in items] == [bad.id]
    assert (fine.notice, bad.notice, busy.notice) == ("quiet", None, "quiet")


# --- sending --------------------------------------------------------------------------------


def test_digest_waits_for_the_queue_then_goes_once(session, settings, receiver):
    r = receiver()
    sender = notify.Sender(f"json://127.0.0.1:{r.port}/hook")
    a = ha_target(session)
    b = ha_target(session, name="Cards", source="x/cards", hacs_kind="card")
    first = scan(session, a, "1.0.0", 30)
    scan(session, b, "1.0.0", status="queued", at=None)  # the queue isn't empty
    assert notify.run_once(session, sender, settings, NOW) is False
    assert r.posts == []

    for s in session.scalars(select(Scan).where(Scan.status == "queued")):
        s.status, s.score, s.verdict, s.finished_at = "done", 50, "Very Sus", NOW
    session.commit()
    assert notify.run_once(session, sender, settings, NOW + MIN) is True
    [post] = r.posts
    assert post["path"] == "/hook" and post["title"] == "Scentry: 2 notices"
    assert post["type"] == "failure"
    assert "Auto Backup (jc/auto-backup) 1.0.0 scores 30" in post["message"]
    assert "\n\nInstalled in Home Assistant: x/cards 1.0.0 scores 50" in post["message"]
    assert f"https://scentry.lan/scans/{first.id}" in post["message"]
    assert notify.run_once(session, sender, settings, NOW + 2 * MIN) is False  # said once
    assert len(r.posts) == 1
    assert session.get(NotifyState, 1).last_sent_at == NOW + MIN


def test_waits_no_longer_than_the_deadline(session, settings, receiver):
    r = receiver()
    sender = notify.Sender(f"json://127.0.0.1:{r.port}/")
    scan(session, ha_target(session), "1.0.0", 30)
    other = ha_target(session, source="o/busy")
    scan(session, other, "1.0.0", status="running", at=None)
    assert notify.run_once(session, sender, settings, NOW) is False
    later = NOW + datetime.timedelta(minutes=settings.notify_max_wait_minutes)
    assert notify.run_once(session, sender, settings, later) is True
    assert r.posts[0]["title"] == "Scentry: Installed in Home Assistant"


def test_failed_send_backs_off_and_hides_secrets(session, settings, receiver):
    r = receiver(status=500)
    sender = notify.Sender(f"json://127.0.0.1:{r.port}/hook/SuperSecretToken?key=hunter22")
    assert (sender.services, sender.invalid) == (1, 0)
    s = scan(session, ha_target(session), "1.0.0", 30)
    assert notify.run_once(session, sender, settings, NOW) is False
    state = session.get(NotifyState, 1)
    assert state.failures == 1 and state.error and s.notice is None
    assert "SuperSecretToken" not in state.error and "hunter22" not in state.error
    assert notify.run_once(session, sender, settings, NOW + MIN // 2) is False  # backing off
    assert len(r.posts) == 1
    r.status = 200
    assert notify.run_once(session, sender, settings, NOW + 2 * MIN) is True
    assert (state.failures, state.error, s.notice) == (0, None, "sent")


def test_secret_parts():
    parts = notify._secret_parts([
        "tgram://123456:ABCDEF-bot-token/987654", "ntfys://user:pa55word@ntfy.lan/my-topic",
        "json://ha.lan:8123/api/webhook/abc123?x=valuevalue",
        "mailtos://me%40mx.org:app-pw-123@mx.org:465?smtp=smtp.mx.org&mode=ssl"])  # fmt: skip
    assert {"123456:ABCDEF-bot-token", "987654", "pa55word", "my-topic", "abc123",
            "valuevalue", "app-pw-123"} <= parts  # fmt: skip
    assert not {"ntfy.lan", "ha.lan", "smtp.mx.org"} & parts


def test_bad_urls_are_counted():
    sender = notify.Sender("json://127.0.0.1:9/a, nonsense://x  ")
    assert (sender.services, sender.invalid) == (1, 1)
    assert notify.Sender("").services == 0


def test_test_message_and_hass_outage(session, settings, receiver):
    r = receiver()
    sender = notify.Sender(f"json://127.0.0.1:{r.port}/")
    state = notify.state_row(session)
    state.test_requested_at = NOW - MIN
    session.add(HassSync(id=1, error="can't reach Home Assistant"))
    session.commit()
    notify.run_once(session, sender, settings, NOW)
    assert [p["title"] for p in r.posts] == ["Scentry: test"]
    assert state.test_ok and state.test_done_at == NOW

    later = NOW + notify.HASS_GRACE
    assert notify.run_once(session, sender, settings, later) is True
    assert r.posts[-1]["title"] == "Scentry: Home Assistant sync failing"
    assert "failing for 30 minutes" in r.posts[-1]["message"]
    assert notify.run_once(session, sender, settings, later + MIN) is False  # once per outage
    session.get(HassSync, 1).error = None
    notify.run_once(session, sender, settings, later + 2 * MIN)
    assert (state.hass_failing_since, state.hass_alerted) == (None, False)
