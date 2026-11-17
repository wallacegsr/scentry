"""What an update changes (Barkley's comparison) and advisories asked again."""

from __future__ import annotations

import datetime
import json
import sys
import types
from pathlib import Path

import pytest
from sqlalchemy import select

from scentry import db, notify, pipeline, updates, worker
from scentry.config import Settings
from scentry.models import Finding, Scan, Target, utcnow
from scentry.proc import Result
from scentry.scanners import barkley
from scentry.scanners.barkley import Barkley
from scentry.scanners.base import ScanContext, Scanner, ScannerRun

DAY = datetime.timedelta(hours=24)


@pytest.fixture
def settings(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    return Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'u.db'}",
                    work_dir=str(work), admin_password="pw",
                    barkley_store=str(tmp_path / "barkley.db"))  # fmt: skip


@pytest.fixture
def session(settings):
    db.configure(settings.database_url)
    with db.SessionLocal() as s:
        yield s


def report(score, *findings, label=None):
    return {"schema_version": 1, "score": score, "complete": True,
            "verdict": {"label": label or ("Good Boy" if score >= 90 else "Very Sus")},
            "graph": {}, "findings": [
                {"rule_id": rule, "title": rule, "severity": sev, "analyzer": "osv"}
                for rule, sev in findings]}  # fmt: skip


def diff(old, new, *changes):
    return {"diff_version": 1, "headline_rank": 40,
            "score": {"from": old["score"], "to": new["score"],
                      "delta": new["score"] - old["score"]},
            "summary": {"findings": {"+": len(changes), "-": 0, "~": 0}}, "warnings": [],
            "changes": [{"kind": "new_finding", "rank": rank, "group": "findings", "sign": "+",
                         "text": text, "severity": sev, "finding_ids": []}
                        for text, sev, rank in changes]}  # fmt: skip


class FakeBarkley(Scanner):
    """Barkley's result for a version, without Barkley."""

    name, executable = "barkley", "python"

    def __init__(self, reports: dict[str, dict], ids: dict[str, int] | None = None):
        self.reports, self.ids = reports, ids or {}

    def run(self, ctx):
        r = self.reports[ctx.ref]
        return ScannerRun("barkley", "ok", findings=barkley.findings_of(r), extra={
            "score": r["score"], "verdict": r["verdict"]["label"], "complete": True,
            "ref": ctx.ref, "report": r, "barkley_id": self.ids.get(ctx.ref)})  # fmt: skip


@pytest.fixture
def compared(monkeypatch):
    """Barkley's comparison, faked: records each pair compared."""
    pairs = []

    def fake(old, new, work, timeout):
        assert Path(work).is_dir()
        pairs.append((old["score"], new["score"]))
        return diff(old, new, ("a finding", "high", 60))

    monkeypatch.setattr(barkley, "compare", fake)
    return pairs


def hacs(session, installed="1.0", available="1.0"):
    t = Target(name="Auto Backup", profile="ha", source="jc/auto-backup", origin="hacs",
               installed_version=installed, available_version=available, ref=installed)  # fmt: skip
    session.add(t)
    session.commit()
    return t


def run(session, settings, target, ref, scanner):
    s = worker.enqueue(session, target, ref)
    pipeline.run_scan(session, worker.claim(session), settings, [scanner])
    session.refresh(s)
    return s


# --- the Barkley adapter ---------------------------------------------------------------


def test_scan_is_stored_in_barkleys_store(tmp_path, settings, monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(report(80)))
        return Result(0, "a human report", "🐕 stored as scan #7 in\n/cache/barkley/scans.db\n")

    monkeypatch.setattr("scentry.scanners.barkley.proc.run", fake_run)
    ctx = ScanContext(settings, "ha", "owner/repo", "v1", tmp_path)
    got = Barkley().run(ctx)
    assert seen["cmd"][-2:] == ["--store", settings.barkley_store]
    assert "--json" not in seen["cmd"]  # Barkley names the stored scan only without it
    assert got.extra["barkley_id"] == 7

    unstored = ScanContext(settings.model_copy(update={"barkley_store": ""}), "ha",
                           "owner/repo", "v1", tmp_path)  # fmt: skip
    got = Barkley().run(unstored)
    assert seen["cmd"][-1] == "--json" and got.extra["barkley_id"] is None


def test_compare_runs_barkleys_offline_diff(tmp_path, monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        old, new = (json.loads(Path(p).read_text()) for p in cmd[2:4])
        Path(cmd[-1]).write_text(json.dumps(diff(old, new)))
        return Result(0, "", "")

    monkeypatch.setattr("scentry.scanners.barkley.proc.run", fake_run)
    out = barkley.compare(report(90), report(60), tmp_path, 60)
    assert out["score"]["delta"] == -30
    assert seen["cmd"][:2] == ["sniff-test", "diff"] and "--offline" in seen["cmd"]

    monkeypatch.setattr("scentry.scanners.barkley.proc.run",
                        lambda cmd, **kw: Result(2, "", "boom"))  # fmt: skip
    with pytest.raises(barkley.BarkleyError, match="boom"):
        barkley.compare(report(90), report(60), tmp_path, 60)


def test_recheck_runs_the_script_with_barkleys_python(tmp_path, monkeypatch):
    monkeypatch.setattr(barkley, "barkley_python", lambda: "/opt/tools/barkley/bin/python")
    answer = {}

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["/opt/tools/barkley/bin/python", "-I"]
        assert Path(cmd[2]).is_file() and cmd[3:5] == ["/s.db", "7"]
        Path(cmd[5]).write_text(json.dumps(answer))
        return Result(0, "", "")

    monkeypatch.setattr("scentry.scanners.barkley.proc.run", fake_run)
    answer.update(state="same")
    assert barkley.recheck("/s.db", 7, tmp_path, 60).state == "same"
    answer.update(state="changed", barkley_id=8, report={**report(50), "context": {}})
    got = barkley.recheck("/s.db", 7, tmp_path, 60)
    assert (got.state, got.barkley_id, got.report["score"]) == ("changed", 8, 50)
    assert "context" not in got.report
    answer.update(state="changed", report={"schema_version": 9})
    assert barkley.recheck("/s.db", 7, tmp_path, 60).state == "error"
    answer.clear()
    answer.update(state="error", detail="osv-scanner error: offline")
    got = barkley.recheck("/s.db", 7, tmp_path, 60)
    assert (got.state, got.detail) == ("error", "osv-scanner error: offline")

    monkeypatch.setattr(barkley, "barkley_python", lambda: None)
    assert barkley.recheck("/s.db", 7, tmp_path, 60).state == "error"


def test_barkley_python_from_the_command(tmp_path, monkeypatch):
    exe = tmp_path / "sniff-test"
    exe.write_text(f"#!{sys.executable}\nimport sys\n")
    monkeypatch.setattr(barkley.shutil, "which", lambda name: str(exe))
    assert barkley.barkley_python() == sys.executable
    exe.write_text("#!/nowhere/python\n")
    assert barkley.barkley_python() is None
    exe.write_bytes(b"\x7fELF binary")
    assert barkley.barkley_python() is None


def test_the_script_uses_barkleys_recheck_and_store(tmp_path, monkeypatch):
    from scentry.scanners import barkley_recheck

    class RecheckError(Exception):
        pass

    class Store:
        saved: list = []
        notes: dict = {}
        has_inputs = True
        outcome: object = None

        def __init__(self, path):
            assert path == "/s.db"

        def get(self, sid):
            return types.SimpleNamespace(id=sid, scanned_at="2026-11-10T00:00:00") if sid else None

        def inputs(self, sid):
            return {"version": 1} if Store.has_inputs else None

        def report(self, sid):
            return report(90)

        def save(self, rep, inputs=None):
            Store.saved.append((rep, inputs))
            return 12

        def link_source(self, sid, like):
            assert (sid, like) == (12, 7)

        def note_recheck(self, sid, result):
            Store.notes[sid] = result

    def recheck(rep, inputs, of, code_scanned_at):
        assert (of, code_scanned_at) == (7, "2026-11-10T00:00:00")
        if isinstance(Store.outcome, Exception):
            raise Store.outcome
        return Store.outcome

    pkg = types.ModuleType("sniff_test")
    pkg.recheck = types.SimpleNamespace(recheck=recheck, RecheckError=RecheckError)
    pkg.store = types.SimpleNamespace(Store=Store)
    monkeypatch.setitem(sys.modules, "sniff_test", pkg)
    monkeypatch.setitem(sys.modules, "sniff_test.recheck", pkg.recheck)
    monkeypatch.setitem(sys.modules, "sniff_test.store", pkg.store)
    out = tmp_path / "out.json"

    def answer(sid=7):
        barkley_recheck.main(["/s.db", str(sid), str(out)])
        return json.loads(out.read_text())

    assert answer() == {"state": "same"} and Store.notes[7] == "same"
    Store.outcome = report(40, ("dep-vuln", "critical"))
    got = answer()
    assert got["state"] == "changed" and got["barkley_id"] == 12
    assert Store.saved[-1] == (Store.outcome, {"version": 1}) and Store.notes[7] == "changed: #12"
    Store.outcome = RecheckError("osv-scanner couldn't reach OSV")
    assert answer() == {"state": "error", "detail": "osv-scanner couldn't reach OSV"}
    Store.has_inputs = False
    assert answer()["state"] == "error"
    assert answer(0)["detail"].startswith("Barkley's store has no scan")


# --- what an update changes ------------------------------------------------------------


def test_offered_update_compared_with_the_installed_version(session, settings, compared):
    t = hacs(session, "1.0", "1.0")
    reports = {"1.0": report(95), "1.1": report(70), "1.2": report(60)}
    first = run(session, settings, t, "1.0", FakeBarkley(reports))
    assert first.diff is None  # nothing earlier

    t.available_version = "1.1"
    session.commit()
    offered = run(session, settings, t, "1.1", FakeBarkley(reports))
    assert offered.diff_from == first.id and compared[-1] == (95, 70)
    assert offered.headline[0]["text"] == "a finding"

    # The installed version scanned again: the offer is compared with that scan.
    again = run(session, settings, t, "1.0", FakeBarkley(reports))
    assert again.diff is None  # 1.1 is newer, not an earlier version of it
    session.refresh(offered)
    assert offered.diff_from == again.id

    # Installed 1.1, nothing offered: compared with the version before it.
    t.installed_version = t.available_version = "1.1"
    session.commit()
    now_installed = run(session, settings, t, "1.1", FakeBarkley(reports))
    assert now_installed.diff_from == again.id


def test_a_failed_comparison_never_fails_the_scan(session, settings, monkeypatch):
    def broken(*a):
        raise barkley.BarkleyError("no comparison")

    monkeypatch.setattr(barkley, "compare", broken)
    t = hacs(session, "1.0", "1.1")
    reports = {"1.0": report(95), "1.1": report(70)}
    run(session, settings, t, "1.0", FakeBarkley(reports))
    offered = run(session, settings, t, "1.1", FakeBarkley(reports))
    assert offered.status == "done" and offered.diff is None and offered.score == 70


# --- advisories asked again ------------------------------------------------------------


@pytest.fixture
def rechecks(monkeypatch):
    """Barkley's re-check, faked: answers from a queue, records the stored ids asked."""
    asked, answers = [], []

    def fake(store, barkley_id, work, timeout):
        asked.append(barkley_id)
        return answers.pop(0)

    monkeypatch.setattr(barkley, "recheck", fake)
    return asked, answers


def test_recheck_when_due_and_what_it_leaves(session, settings, compared, rechecks):
    asked, answers = rechecks
    t = hacs(session, "1.0", "1.0")
    first = run(session, settings, t, "1.0", FakeBarkley({"1.0": report(95)}, {"1.0": 7}))
    assert first.barkley_id == 7
    assert first.advisories_next_at == pytest.approx(utcnow() + DAY, abs=datetime.timedelta(
        minutes=1))  # fmt: skip
    now = utcnow()
    assert updates.recheck_due(session, settings, now) is False  # not a day yet

    later = now + DAY + datetime.timedelta(minutes=5)
    answers.append(barkley.Recheck("same"))
    assert updates.recheck_due(session, settings, later) is True and asked == [7]
    session.refresh(first)
    assert first.advisories_checked_at == later and first.advisories_next_at == later + DAY
    assert updates.recheck_due(session, settings, later) is False

    answers.append(barkley.Recheck("error", "osv-scanner couldn't reach OSV"))
    when = later + DAY
    updates.recheck_due(session, settings, when)
    session.refresh(first)
    assert first.advisories_error and first.advisories_next_at == when + updates.RETRY

    changed = report(50, ("dep-vuln", "critical"))
    answers.append(barkley.Recheck("changed", report=changed, barkley_id=8))
    when += updates.RETRY
    updates.recheck_due(session, settings, when)
    new = session.scalars(select(Scan).where(Scan.kind == "recheck")).one()
    assert (new.recheck_of, new.ref, new.score, new.barkley_id) == (first.id, "1.0", 50, 8)
    assert new.diff_from == first.id and compared[-1] == (95, 50)
    session.refresh(first)
    assert first.advisories_error is None
    vuln = session.scalars(select(Finding)).one()  # the newest scan: findings follow it
    assert (vuln.rule_id, vuln.status, vuln.opened_scan_id) == ("dep-vuln", "open", new.id)

    # Next time it's the re-check that is asked again, not the scan it replaced.
    answers.append(barkley.Recheck("same"))
    updates.recheck_due(session, settings, when + DAY)
    assert asked[-1] == 8

    # A re-check is no scan of the code: the weekly rescan still comes on time.
    t.interval_hours = 168
    session.commit()
    assert worker.schedule_due(session, first.finished_at + datetime.timedelta(hours=169)) == 1


def test_which_versions_are_rechecked(session, settings, rechecks):
    t = hacs(session, "1.0", "1.1")
    reports = {"0.9": report(95), "1.0": report(95), "1.1": report(90)}
    ids = {"0.9": 6, "1.0": 7, "1.1": 8}
    for ref in ("0.9", "1.0", "1.1"):
        run(session, settings, t, ref, FakeBarkley(reports, ids))
    assert sorted(s.barkley_id for s in updates.candidates(session)) == [7, 8]  # not 0.9

    worker.enqueue(session, t, "1.1")  # a fresh scan is coming: wait for it
    assert updates.candidates(session) == []
    session.execute(Scan.__table__.delete().where(Scan.status == "queued"))
    t.hacs_removed_at = utcnow()  # uninstalled
    session.commit()
    assert updates.candidates(session) == []

    hand = Target(name="x", profile="ha", source="o/x")
    session.add(hand)
    session.commit()
    run(session, settings, hand, None, FakeBarkley({None: report(90)}, {None: 9}))
    assert [s.barkley_id for s in updates.candidates(session)] == [9]

    off = settings.model_copy(update={"barkley_store": ""})
    assert updates.due(session, off, utcnow() + 2 * DAY) is None
    never = settings.model_copy(update={"recheck_hours": 0})
    assert updates.due(session, never, utcnow() + 2 * DAY) is None


def test_recheck_of_an_older_scan_leaves_the_findings(session, settings, compared, rechecks):
    _, answers = rechecks
    t = hacs(session, "1.0", "1.1")
    reports = {"1.0": report(95), "1.1": report(90, ("dep-other", "low"))}
    installed = run(session, settings, t, "1.0", FakeBarkley(reports, {"1.0": 7}))
    run(session, settings, t, "1.1", FakeBarkley(reports))  # not stored: no re-check
    answers.append(barkley.Recheck("changed", report=report(50, ("dep-vuln", "critical")),
                                   barkley_id=10))  # fmt: skip
    new = updates.recheck(session, installed, settings)
    assert new.kind == "recheck" and new.score == 50
    assert [f.rule_id for f in session.scalars(select(Finding))] == ["dep-other"]


def test_new_advisory_is_announced(session, settings):
    t = hacs(session, "1.0", "1.0")
    base = Scan(target_id=t.id, ref="1.0", status="done", score=95, verdict="Good Boy",
                finished_at=utcnow(), complete=True, report=report(95))  # fmt: skip
    session.add(base)
    session.commit()
    worse = report(88, ("dep-vuln", "high"))
    new = Scan(target_id=t.id, ref="1.0", status="done", score=88, verdict="Kinda Sus",
               finished_at=utcnow(), complete=True, report=worse, kind="recheck",
               recheck_of=base.id, diff_from=base.id,
               diff=diff(base.report, worse,
                         ("dep-vuln: requests 2.0 <x@y>", "high", 70)))  # fmt: skip
    session.add(new)
    session.commit()
    item = notify.evaluate(session, new, settings)
    assert item.head == "New advisory" and item.level == "warning"
    assert "Auto Backup (jc/auto-backup) 1.0 (installed) now scores 88" in item.text
    assert "(was 95, Good Boy)" in item.text
    assert item.lines == ["new high: dep-vuln requests 2.0 x y"]

    new.diff = diff(base.report, worse)  # only lower, nothing serious added: quiet
    new.score = 90
    assert notify.evaluate(session, new, settings) is None


def test_offered_update_message_lists_what_it_changes(session, settings):
    t = hacs(session, "1.0", "1.1")
    installed = Scan(target_id=t.id, ref="1.0", status="done", score=95, verdict="Good Boy",
                     finished_at=utcnow(), complete=True, report=report(95))  # fmt: skip
    session.add(installed)
    session.commit()
    offered = Scan(target_id=t.id, ref="1.1", status="done", score=60, verdict="Very Sus",
                   finished_at=utcnow(), complete=True, report=report(60), diff_from=installed.id,
                   diff=diff(installed.report, report(60),
                             ("now sends data to a.example", "high", 80),
                             ("minor", "low", 10)))  # fmt: skip
    session.add(offered)
    session.commit()
    item = notify.evaluate(session, offered, settings)
    assert item.head == "Update offered: look before installing"
    assert item.lines == ["new high: now sends data to a.example"]  # the headline only


def test_scan_page_shows_the_comparison_and_rechecks(tmp_path):
    from fastapi.testclient import TestClient

    from scentry.web.app import create_app

    s = Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'web.db'}",
                 admin_password="pw")  # fmt: skip
    client = TestClient(create_app(s), follow_redirects=False)
    auth = ("admin", "pw")
    with db.SessionLocal() as session:
        t = hacs(session, "1.0", "1.1")
        old = Scan(target_id=t.id, ref="1.0", status="done", score=95, report=report(95),
                   barkley_id=7, finished_at=utcnow())  # fmt: skip
        session.add(old)
        session.commit()
        new = Scan(target_id=t.id, ref="1.1", status="done", score=60, report=report(60),
                   diff_from=old.id, finished_at=utcnow(),
                   diff=diff(old.report, report(60), ("<script>x</script>", "high", 80),
                             ("small thing", "low", 5)))  # fmt: skip
        re = Scan(target_id=t.id, ref="1.0", status="done", score=80, kind="recheck",
                  recheck_of=old.id, finished_at=utcnow())  # fmt: skip
        session.add_all([new, re])
        session.commit()
        ids, tid = (old.id, new.id, re.id), t.id

    page = client.get(f"/scans/{ids[1]}", auth=auth).text
    assert "What changed since" in page and "95 → 60" in page and "(-35)" in page
    assert "&lt;script&gt;x&lt;/script&gt;" in page and "<script>x" not in page
    assert "1 smaller change" in page and "small thing" in page
    assert "Check advisories again" not in page  # not in Barkley's store

    page = client.get(f"/scans/{ids[0]}", auth=auth).text
    assert "Check advisories again" in page and f"/scans/{ids[2]}" in page
    assert client.post(f"/scans/{ids[0]}/recheck", auth=auth).status_code == 303
    with db.SessionLocal() as session:
        assert session.get(Scan, ids[0]).advisories_next_at <= utcnow()
    assert client.post(f"/scans/{ids[1]}/recheck", auth=auth).status_code == 404

    assert "advisories re-checked" in client.get(f"/scans/{ids[2]}", auth=auth).text
    assert "advisories re-checked" in client.get(f"/targets/{tid}", auth=auth).text
    exported = client.get(f"/targets/{tid}/export.json", auth=auth).json()["target"]
    kinds = {s["id"]: (s["kind"], s["recheck_of"], s["diff_from"]) for s in exported["scans"]}
    assert kinds[ids[2]] == ("recheck", ids[0], None) and kinds[ids[1]][2] == ids[0]
