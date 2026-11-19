"""What Scentry borrows from Barkley's panel: cards or a table, a finding in plain words,
where an app's data can go, what it can do inside Home Assistant, and the developer's
security habits."""

from __future__ import annotations

import collections
import datetime
import json
import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scentry import db, findings, pipeline, sarif, updates, worker
from scentry.config import Settings
from scentry.models import Finding, Scan, Target, utcnow
from scentry.proc import Result
from scentry.scanners import barkley
from scentry.scanners.base import RawFinding, Scanner, ScannerRun
from scentry.web import report as rp
from scentry.web.app import create_app

AUTH = ("admin", "pw")
TODAY = datetime.date(2026, 11, 18)
SUBJECT = "integration:legit"
EVIL = "<i>alerts</i>.example"  # a site's name comes from the scanned code


def edge(source, target, relation, attrs=None, *, evidence="possible", finding_ids=()):
    return {"source": source, "target": target, "relation": relation, "evidence": evidence,
            "finding_ids": list(finding_ids), "attrs": attrs or {},
            "samples": [{"file": "legit/__init__.py", "line": 20}]}  # fmt: skip


def app_report(host="alerts.example"):
    """A Barkley report of an integration that reads secrets and logins, sends them out,
    and runs a server the developer hosts."""
    nodes = [(SUBJECT, "integration", "legit"),
             ("auth:users and tokens", "auth", "users and tokens"),
             ("data:secrets.yaml", "data", "secrets.yaml"), ("data:weather", "data", "weather"),
             (f"host:{host}", "host", host),
             ("host:stats.dev.example", "host", "stats.dev.example"),
             ("host:github.com", "host", "github.com"), ("host:192.168.1.5", "host", "192.168.1.5"),
             ("port:1883", "port", "1883"), ("network:off-box", "network", "off-box")]  # fmt: skip
    edges = [
        edge(SUBJECT, f"host:{host}", "connects_to", {"class": "undeclared", "schemes": ["https"]}),
        edge(SUBJECT, "host:stats.dev.example", "connects_to", {"class": "developer_hosted"}),
        edge(SUBJECT, "host:github.com", "connects_to", {"class": "infrastructure"}),
        edge(SUBJECT, "host:192.168.1.5", "connects_to", {"class": "local"}),
        edge(SUBJECT, "port:1883", "uses_port", {"directions": ["out"]}),
        edge(SUBJECT, "auth:users and tokens", "reads", finding_ids=["f1"]),
        edge(SUBJECT, "data:secrets.yaml", "reads", finding_ids=["f2"]),
        edge(SUBJECT, "data:weather", "reads"),
        edge("data:secrets.yaml", f"host:{host}", "flows_to"),
        edge("auth:users and tokens", "network:off-box", "flows_to", evidence="proven"),
    ]
    return {
        "schema_version": 1, "score": 0, "complete": True, "verdict": {"label": "BORK BORK BORK"},
        "target": {"kind": "integration", "repo": "dev/legit"},
        "graph": {"graph_version": 1, "subject": SUBJECT, "edges": edges,
                  "nodes": [{"id": i, "kind": k, "label": label} for i, k, label in nodes]},
        "hygiene": {"scanners": [{"name": "CodeQL", "kind": "code"}], "dependabot": ["pip"],
                    "renovate": False, "security_policy": "SECURITY.md",
                    "update_prs": {"open": 0, "oldest_days": None},
                    "security_issues": {"open": 0, "of": 12, "items": []},
                    "dependabot_but_known_vulns": False, "errors": []},
        "findings": [
            {"rule_id": "ha-exfil-taint", "title": "Sensitive HA data sent off-box",
             "severity": "critical", "category": "exfil", "file": "legit/__init__.py", "line": 20,
             "evidence": "requests.post(URL, data=token)"},
            {"rule_id": "dep-vuln", "title": "Dependency with known vulnerabilities",
             "severity": "medium", "category": "dependency", "file": "manifest.json",
             "evidence": "requests@2.0.0 (PyPI): GHSA-2xpw-w6gg-jr37",
             "dependency": {"package": "requests", "ecosystem": "PyPI", "version": "2.0.0",
                            "direct": True, "fixed_in": "2.32.4", "latest": "2.32.5",
                            "latest_date": "2025-08-18", "behind": 40,
                            "advisories": [{"id": "GHSA-2xpw-w6gg-jr37",
                                            "aliases": ["CVE-2025-66471", "PYSEC-2026-1994"],
                                            "summary": "Leaks things"}]}},
        ],
    }  # fmt: skip


PLAIN = {
    "version": 1, "barkley": "0.13.0",
    "rules": {
        "ha-exfil-taint": {"title": "Sends private Home Assistant data out of your home",
                           "means": "It sends your data out.",
                           "worry": "Yes, until you know where.",
                           "chip": "Sends your data out",
                           "links": [["How Barkley checks this",
                                      "https://example.org/rules/ha-exfil-taint"]]},
        "dep-vuln": {"title": "Uses a code library with known security bugs",
                     "means": "A library has known bugs.", "worry": "Depends on the bug.",
                     "chip": "Outdated library", "links": []},
    },
    "can_do": ["Makes web requests", "Reads the state of your devices"],
    "data_labels": {"users and tokens": "Users and login tokens",
                    "secrets.yaml": "Your secrets file"},
    "ports": {"1883": "MQTT"},
    "privacy": [{"kind": "telemetry", "label": "Telemetry",
                 "title": "Can send usage statistics to the developer",
                 "means": "It contacts a server the developer runs.",
                 "unknown": "Whether it is switched on.", "hosts": ["stats.dev.example"],
                 "where": ["legit/__init__.py:20"]}],
}  # fmt: skip


# --- Barkley's plain words, asked of Barkley ---------------------------------------------


def test_clean_plain_keeps_shapes_and_sizes():
    got = barkley.clean_plain({
        "version": 1, "barkley": "0.13.0", "extra": "dropped",
        "rules": {"r1": {"title": "T" * 400, "means": "m", "worry": "w", "chip": "c",
                         "links": [["Docs", "https://example.org/r1"],
                                   ["Script", "javascript:alert(1)"], ["half"]]},
                  "r2": "not a rule"},
        "can_do": ["Makes web requests", 5],
        "data_labels": {"secrets.yaml": "Your secrets file"},
        "ports": {"1883": "MQTT", "mqtt": "not a port"},
        "privacy": [{"label": "Telemetry", "title": "t", "hosts": [f"h{i}" for i in range(9)]},
                    "junk"],
    })  # fmt: skip
    r1 = got["rules"]["r1"]
    assert len(r1["title"]) == 301 and r1["links"] == [["Docs", "https://example.org/r1"]]
    assert set(got["rules"]) == {"r1"} and "extra" not in got
    assert got["can_do"] == ["Makes web requests"] and got["ports"] == {"1883": "MQTT"}
    assert len(got["privacy"]) == 1 and got["privacy"][0]["hosts"] == [f"h{i}" for i in range(6)]
    assert (got["version"], got["barkley"]) == (1, "0.13.0")


def test_plain_runs_the_script_with_barkleys_python(tmp_path, monkeypatch):
    monkeypatch.setattr(barkley, "barkley_python", lambda: "/opt/tools/barkley/bin/python")
    answer: dict = {}

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["/opt/tools/barkley/bin/python", "-I"]
        assert Path(cmd[2]).name == "barkley_plain.py" and Path(cmd[2]).is_file()
        assert json.loads(Path(cmd[3]).read_text("utf-8"))["graph"]["subject"] == SUBJECT
        if answer:
            Path(cmd[4]).write_text(json.dumps(answer), "utf-8")
        return Result(0, "", "")

    monkeypatch.setattr("scentry.scanners.barkley.proc.run", fake_run)
    answer.update(PLAIN)
    assert barkley.plain(app_report(), tmp_path, 60) == barkley.clean_plain(PLAIN)
    assert not (tmp_path / "plain-report.json").exists()
    answer.clear()
    answer.update(error="ImportError: no explain")
    assert barkley.plain(app_report(), tmp_path, 60) == {"error": "ImportError: no explain"}
    answer.clear()
    answer.update(version=2)
    assert barkley.plain(app_report(), tmp_path, 60) == {"error": "unsupported version 2"}
    answer.clear()  # the script wrote nothing: none this time, asked again later
    assert barkley.plain(app_report(), tmp_path, 60) is None
    monkeypatch.setattr(barkley, "barkley_python", lambda: None)
    assert barkley.plain(app_report(), tmp_path, 60) is None


def test_the_plain_script_asks_barkleys_explain_and_privacy(tmp_path, monkeypatch):
    from scentry.scanners import barkley_plain

    def explain(rule_id):
        return types.SimpleNamespace(title=f"About {rule_id}", means="m", worry="w", chip="c",
                                     links=[("Docs", f"https://example.org/{rule_id}"),
                                            ("Local", "file:///etc/passwd")])  # fmt: skip

    note = types.SimpleNamespace(kind="telemetry", label="Telemetry", title="t", means="m",
                                 unknown="u", hosts=[f"h{i}" for i in range(8)], where=["a.py:1"])
    pkg = types.ModuleType("sniff_test")
    pkg.__version__ = "0.13.0"
    report = types.ModuleType("sniff_test.report")
    report.explain = types.SimpleNamespace(explain=explain, data_label=str.title,
                                           can_do=lambda rep: ["Makes web requests"])
    report.privacy = types.SimpleNamespace(notes=lambda rep: [note])
    endpoints = types.ModuleType("sniff_test.analyzers.endpoints")
    endpoints.WELL_KNOWN_PORTS = {1883: ("MQTT", "unencrypted")}
    for name, module in (("sniff_test", pkg), ("sniff_test.report", report),
                         ("sniff_test.analyzers", types.ModuleType("sniff_test.analyzers")),
                         ("sniff_test.analyzers.endpoints", endpoints)):  # fmt: skip
        monkeypatch.setitem(sys.modules, name, module)
    src, out = tmp_path / "report.json", tmp_path / "out.json"
    src.write_text(json.dumps(app_report()), "utf-8")

    assert barkley_plain.main([str(src), str(out)]) == 0
    got = json.loads(out.read_text("utf-8"))
    assert (got["version"], got["barkley"], got["can_do"]) == (1, "0.13.0", ["Makes web requests"])
    assert set(got["rules"]) == {"ha-exfil-taint", "dep-vuln"}
    assert got["rules"]["dep-vuln"]["links"] == [["Docs", "https://example.org/dep-vuln"]]
    assert got["data_labels"] == {"users and tokens": "Users And Tokens",
                                  "secrets.yaml": "Secrets.Yaml", "weather": "Weather"}
    assert got["ports"] == {"1883": "MQTT"}
    assert got["privacy"][0]["hosts"] == [f"h{i}" for i in range(6)]

    report.explain = None  # Barkley changed: an error, never half the words
    barkley_plain.main([str(src), str(out)])
    assert json.loads(out.read_text("utf-8"))["error"].startswith("AttributeError")


@pytest.fixture
def settings(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    return Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'p.db'}",
                    work_dir=str(work), admin_password="pw",
                    barkley_store=str(tmp_path / "barkley.db"))  # fmt: skip


@pytest.fixture
def session(settings):
    db.configure(settings.database_url)
    with db.SessionLocal() as s:
        yield s


class FakeBarkley(Scanner):
    name, executable = "barkley", "python"

    def __init__(self, report, plain):
        self.report, self.plain = report, plain

    def run(self, ctx):
        return ScannerRun("barkley", "ok", findings=barkley.findings_of(self.report), extra={
            "score": 0, "verdict": "BORK BORK BORK", "complete": True, "ref": ctx.ref,
            "report": self.report, "plain": self.plain})  # fmt: skip


def test_a_scan_keeps_the_report_and_plain_words(session, settings):
    t = Target(name="Legit", profile="ha", source="dev/legit", origin="hacs",
               installed_version="1.0", available_version="1.0", ref="1.0")  # fmt: skip
    session.add(t)
    session.commit()
    scans = []
    for plain in (PLAIN, None):
        s = worker.enqueue(session, t, "1.0")
        scanner = FakeBarkley(app_report(), plain)
        pipeline.run_scan(session, worker.claim(session), settings, [scanner])
        session.refresh(s)
        scans.append(s)
    assert scans[0].report["graph"]["subject"] == SUBJECT and scans[0].plain == PLAIN
    # Not had this time: left unasked (SQL NULL, not JSON null), for the idle worker.
    assert session.scalars(select(Scan.id).where(Scan.plain.is_(None))).all() == [scans[1].id]


def test_older_scans_get_the_words_while_the_runner_is_idle(session, settings, monkeypatch):
    monkeypatch.setattr(barkley, "barkley_python", lambda: None)
    assert not updates.plain_due(session, settings)  # no Barkley here to ask
    monkeypatch.setattr(barkley, "barkley_python", lambda: "/py")
    asked, answers = [], [PLAIN, None]

    def fake(report, work, timeout):
        assert Path(work).is_dir()
        asked.append(report["score"])
        return answers.pop(0)

    monkeypatch.setattr(barkley, "plain", fake)
    t = Target(name="Legit", profile="ha", source="dev/legit")
    session.add(t)
    session.flush()

    def scan(score, status="done", **kw):
        s = Scan(target_id=t.id, status=status, score=score, **kw)
        session.add(s)
        return s

    old = scan(50, report={"score": 50})
    scan(60, report={"score": 60}, plain=PLAIN)
    new = scan(70, report={"score": 70})
    scan(80)  # no report
    scan(90, "failed", report={"score": 90})
    session.commit()
    assert updates.plain_due(session, settings) and updates.plain_due(session, settings)
    assert not updates.plain_due(session, settings)
    assert asked == [70, 50]  # newest first, each once
    assert new.plain == PLAIN and old.plain == {"error": "Barkley couldn't be asked"}


def test_rule_details_from_sarif():
    rules = [
        {"id": "r1", "shortDescription": {"text": "Bad host"},
         "fullDescription": {"text": "Binding every interface exposes it."},
         "helpUri": "https://semgrep.dev/r/r1"},
        {"id": "r2", "fullDescription": {"text": "Message  text."}, "help": {"text": "x"},
         "helpUri": "http://plain.example/r2"},
        {"id": "r3", "help": {"text": "More help."}, "helpUri": "https://bad.example/a b"},
    ]  # fmt: skip
    results = [{"ruleId": r, "level": "warning", "message": {"text": "Message text"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                                    "region": {"startLine": i + 1}}}]}
               for i, r in enumerate(("r1", "r2", "r3"))]  # fmt: skip
    doc = {"runs": [{"tool": {"driver": {"rules": rules}}, "results": results}]}
    got = {f.rule_id: f.details for f in sarif.parse(doc, "semgrep")}
    assert got["r1"] == {"about": "Binding every interface exposes it.",
                         "url": "https://semgrep.dev/r/r1"}  # fmt: skip
    assert got["r2"] is None  # it only repeats the message; the page isn't https
    assert got["r3"] == {"about": "More help."}  # not a well-formed link


# --- the shapes the pages draw -----------------------------------------------------------


def test_the_diagram_draws_reads_destinations_and_paths():
    f = rp.flow(app_report(), PLAIN, "Legit")
    assert f.label == "Where Legit's data can go" and f.caption[0].startswith("Red, solid")
    for d, suffix in ((f.wide, "w"), (f.narrow, "n")):
        texts = {s.text for s in d.shapes if s.kind == "text"}
        assert {"Your secrets file", "Users and login tokens", "weather", "Legit", "Integration",
                "alerts.example", "Somewhere off your box", "Your own network",
                "MQTT server, port 1883", "Server the developer runs",
                "Other internet sites: 1"} <= texts  # fmt: skip
        boxes = collections.Counter(s.cls for s in d.shapes if s.kind == "rect")
        assert boxes == {"box bad": 4, "box": 4, "box priv": 1, "box app": 1}
        assert sorted(s.cls for s in d.shapes if s.marker == "red") == ["leak", "leak maybe"]
        assert d.suffix == suffix
    assert rp.connection_sentence(app_report(), PLAIN) == (
        "Names 3 internet sites and addresses on your own network. Connects to port 1883 (MQTT) "
        "on a device or server it's set up with.")  # fmt: skip

    # Reads nothing, listens on a port: arrows only, pointing in.
    rep = {"graph": {"subject": SUBJECT, "nodes": [{"id": "port:8080", "kind": "port"}],
                     "edges": [edge(SUBJECT, "port:8080", "uses_port", {"directions": ["in"]})]}}
    f = rp.flow(rep, {}, "Legit")
    assert "Reads none of your private data" in {s.text for s in f.wide.shapes}
    assert "Listens on port 8080" in {s.text for s in f.wide.shapes}
    assert f.caption[0].startswith("Arrows")
    assert rp.connection_sentence(rep, {}) == "No internet sites in its code. Listens on port 8080."
    assert rp.flow({"graph": {"subject": SUBJECT, "nodes": [], "edges": []}}, {}, "Legit") is None


def test_habits_and_a_plus():
    rep = app_report()
    items, green = rp.habits(rep)
    assert green and {h.mark for h in items} == {"yes"}
    assert items[0].text == "Runs security scans in its GitHub workflows: CodeQL (code)."
    h = rep["hygiene"]
    h["update_prs"] = {"open": 2, "oldest_days": 3}  # just opened: not left waiting
    items, green = rp.habits(rep)
    assert green and any("2 opened in the last 7 days" in i.text for i in items)
    h["update_prs"] = {"open": 2, "oldest_days": 90}
    items, green = rp.habits(rep)
    assert not green and ("Dependency-update pull requests waiting to be merged: 2, the oldest "
                          "3 months old.") in [i.text for i in items]  # fmt: skip
    h["security_issues"] = {"open": 1, "of": 100, "items": [
        {"number": 42, "title": "Token in logs", "age_days": 0}, {"number": "x"}]}  # fmt: skip
    issue = rp.habits(rep)[0][-1]
    assert issue.text == ("Open issues that look security-related: 1 (among the 100 newest "
                          "open issues).")  # fmt: skip
    assert issue.issues == [{"number": 42, "title": "Token in logs", "age": "opened today",
                             "url": "https://github.com/dev/legit/issues/42"}]  # fmt: skip
    rep["target"]["repo"] = "not a repo/../x"
    assert rp.habits(rep)[0][-1].issues[0]["url"] == ""
    h["errors"] = ["GitHub's rate limit"]
    items, green = rp.habits(rep)
    assert not green and items[-1].text == "Not checked: GitHub's rate limit"
    assert rp.habits({"graph": {}}) is None  # Barkley didn't look


def finding(rule, severity, title="A finding", scanner="barkley", same_as=None):
    return types.SimpleNamespace(rule_id=rule, severity=severity, title=title, scanner=scanner,
                                 same_as=same_as)  # fmt: skip


def test_a_cards_sentence_and_chips():
    scan = types.SimpleNamespace(complete=True, report=app_report())
    found = [finding("dep-vuln", "medium"), finding("ha-exfil-taint", "critical"),
             finding("twin", "critical", same_as=5), finding("noise", "low")]  # fmt: skip
    assert rp.card_sentence("ha", scan, found, PLAIN) == (
        "Sends private Home Assistant data out of your home. And 1 more thing worth a look. "
        "Can send usage statistics to the developer.")  # fmt: skip
    assert rp.card_chips(scan, found, PLAIN) == [
        ("bad", "Sends your data out"), ("warn", "Outdated library"), ("priv", "Telemetry")]
    quiet = {**PLAIN, "privacy": []}
    assert rp.card_sentence("ha", scan, [], quiet) == (
        "No security concerns found. Names 3 internet sites and addresses on your own network. "
        "Connects to port 1883 (MQTT) on a device or server it's set up with.")  # fmt: skip
    many = [finding(f"r{i}", "high", f"Rule {i}") for i in range(5)]
    assert [c for c, _ in rp.card_chips(scan, many, {})] == ["bad", "bad", "bad"]

    unfinished = types.SimpleNamespace(complete=False, report=None)
    assert rp.card_sentence("ha", unfinished, found, PLAIN).startswith("The last scan didn't")
    assert ("priv", "Telemetry") not in rp.card_chips(unfinished, found, PLAIN)
    mine = types.SimpleNamespace(complete=True, report=None)
    assert rp.card_sentence("owned", mine, [finding("x", "low", scanner="bandit")], {}) == (
        "Only minor findings open.")  # fmt: skip
    assert rp.card_sentence("owned", mine, [], {}) == "No open findings."
    assert rp.card_sentence("ha", None, [], {}) == "Not scanned yet."


def test_a_packages_facts_bugs_and_what_to_do():
    dep = app_report()["findings"][1]["dependency"]
    pkg = rp.package(dep, False, TODAY)
    assert pkg.facts == ["fixed in 2.32.4", "the newest is 2.32.5 (2025-08-18), 40 releases newer",
                         "the app asks for it itself"]  # fmt: skip
    assert pkg.stale == ""
    assert [(b.id, b.also, b.summary) for b in pkg.bugs] == [
        ("GHSA-2xpw-w6gg-jr37", ["CVE-2025-66471"], "Leaks things")]
    assert pkg.bugs[0].url == "https://osv.dev/vulnerability/GHSA-2xpw-w6gg-jr37"
    assert rp.package_action(pkg, False).startswith("Home Assistant installs the version")
    mine = rp.package(dep, True, TODAY)
    assert "your code asks for it itself" in mine.facts
    assert rp.package_action(mine, True).startswith("Update requests to 2.32.4 or later.")

    old = rp.package({**dep, "fixed_in": None, "latest_date": "2022-01-01", "direct": False,
                      "ecosystem": "npm"}, False, TODAY)  # fmt: skip
    assert old.facts[0] == "no release fixes it yet"
    assert old.facts[-1] == "it comes in through another library"
    assert old.stale == "No release in over 4 years: likely unmaintained, so a fix may never come."
    assert rp.package_action(old, False).startswith("The library is built into the card's code")
    assert rp.package_action(old, True).startswith("No release of requests fixes it yet")
    assert rp.package({"version": "1.0"}, False, TODAY) is None

    # Any scanner's ids: one that isn't a CVE linked, the rest alongside; odd ones left out.
    bugs = rp.bugs_of({"groups": [["CVE-2025-66471", "GHSA-2xpw-w6gg-jr37"], ["<script>"],
                                  ["CVE-2026-1234"]]})  # fmt: skip
    assert [(b.id, b.also) for b in bugs] == [("GHSA-2xpw-w6gg-jr37", ["CVE-2025-66471"]),
                                              ("CVE-2026-1234", [])]  # fmt: skip


def test_a_finding_is_matched_to_its_reports():
    rep = app_report()
    raw = barkley.findings_of(rep)[1]
    f = types.SimpleNamespace(scanner="barkley", rule_id=raw.rule_id, file=raw.file,
                              line=raw.line, evidence=raw.evidence)  # fmt: skip
    assert rp.report_finding(rep, f) is rep["findings"][1]
    assert rp.report_finding(rep, types.SimpleNamespace(**{**vars(f), "line": 9})) is None
    assert rp.report_finding(rep, types.SimpleNamespace(**{**vars(f), "scanner": "osv"})) is None
    assert rp.report_finding(None, f) is None


# --- the pages -------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path):
    s = Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'web.db'}",
                 admin_password="pw")  # fmt: skip
    return TestClient(create_app(s), follow_redirects=False)


def seed_app(report, plain=None, name="Legit Weather") -> tuple[int, int]:
    """An installed app, scanned, with Barkley's findings."""
    now = utcnow()
    with db.SessionLocal() as session:
        t = Target(name=name, profile="ha", source="dev/legit", origin="hacs",
                   hacs_kind="integration", installed_version="1.0", ref="1.0", hacs_seen_at=now)
        session.add(t)
        session.flush()
        scan = Scan(target_id=t.id, status="done", ref="1.0", score=0, verdict="BORK BORK BORK",
                    complete=True, report=report, finished_at=now)  # fmt: skip
        if plain is not None:
            scan.plain = plain
        session.add(scan)
        session.flush()
        run = ScannerRun("barkley", "ok", findings=barkley.findings_of(report))
        findings.reconcile(session, t, scan, [run], now)
        session.commit()
        return t.id, scan.id


def test_cards_or_a_table_and_the_choice_is_kept(client):
    tid, _ = seed_app(app_report(EVIL), PLAIN)
    assert 'class="app-cards"' not in client.get("/ha", auth=AUTH).text  # a table at first
    r = client.get("/ha?view=cards", auth=AUTH)
    cookie = r.headers["set-cookie"].lower()
    assert "scentry_targets_view=cards" in cookie and "httponly" in cookie
    assert "samesite=lax" in cookie and "secure" not in cookie  # this test's site is http
    assert 'class="app-card look"' in r.text
    assert "Sends private Home Assistant data out of your home. And 1 more thing" in r.text
    assert '<span class="tag priv">Telemetry</span>' in r.text
    assert 'class="app-cards"' in client.get("/ha", auth=AUTH).text  # kept
    assert 'class="app-cards"' in client.get("/ha?view=bogus", auth=AUTH).text
    assert 'class="app-cards"' not in client.get("/ha?view=table", auth=AUTH).text
    assert 'class="app-cards"' not in client.get("/ha", auth=AUTH).text

    # A target's findings: chosen apart from the list of targets.
    r = client.get(f"/targets/{tid}?view=cards", auth=AUTH)
    assert "scentry_findings_view=cards" in r.headers["set-cookie"]
    assert 'class="finding-cards"' in r.text
    assert "Sends private Home Assistant data out of your home" in r.text
    assert 'class="finding-cards"' in client.get(f"/targets/{tid}", auth=AUTH).text
    assert 'class="app-cards"' not in client.get("/ha", auth=AUTH).text


def test_where_its_data_can_go_on_the_target_and_scan_pages(client):
    tid, sid = seed_app(app_report(EVIL), PLAIN)
    for url in (f"/targets/{tid}", f"/scans/{sid}"):
        page = client.get(url, auth=AUTH).text
        assert "Where your data can go" in page
        assert '<svg class="flow flow-w"' in page and '<svg class="flow flow-n"' in page
        assert 'marker-end="url(#arrow-red-w)"' in page and 'marker-end="url(#arrow-red-n)"' in page
        assert "&lt;i&gt;alerts&lt;/i&gt;.example" in page and "<i>alerts" not in page
        assert "Can send usage statistics to the developer" in page
        assert "<li>Makes web requests</li>" in page
        assert "The developer's security habits" in page and "A+ security habits" in page
    bare, _ = seed_app({"schema_version": 1, "findings": []}, name="Old Report")
    page = client.get(f"/targets/{bare}", auth=AUTH).text
    assert "Where your data can go" not in page and "security habits" not in page


def test_a_finding_in_plain_words(client):
    seed_app(app_report(), PLAIN)
    with db.SessionLocal() as session:
        ids = {f.rule_id: f.id for f in session.scalars(select(Finding))}
    page = client.get(f"/findings/{ids['ha-exfil-taint']}", auth=AUTH).text
    assert '<p class="plain-title">Sends private Home Assistant data out of your home</p>' in page
    assert "<dt>What it means</dt><dd>It sends your data out.</dd>" in page
    assert "<dt>Should you worry?</dt><dd>Yes, until you know where.</dd>" in page
    assert ('<a href="https://example.org/rules/ha-exfil-taint" target="_blank" '
            'rel="noopener noreferrer">How Barkley checks this</a>') in page
    assert "What barkley reported" in page and "requests.post(URL, data=token)" in page

    page = client.get(f"/findings/{ids['dep-vuln']}", auth=AUTH).text
    assert ("<strong>requests 2.0.0</strong>: fixed in 2.32.4 · the newest is 2.32.5 "
            "(2025-08-18), 40 releases newer · the app asks for it itself.") in page
    assert ('<a href="https://osv.dev/vulnerability/GHSA-2xpw-w6gg-jr37" target="_blank" '
            'rel="noopener noreferrer">GHSA-2xpw-w6gg-jr37 (CVE-2025-66471)</a>: '
            'Leaks things') in page  # fmt: skip
    assert "Home Assistant installs the version the integration asks for" in page


def test_without_plain_words_the_report_still_tells(client):
    seed_app(app_report())  # the runner hasn't asked Barkley yet
    with db.SessionLocal() as session:
        fid = session.scalar(select(Finding.id).where(Finding.rule_id == "dep-vuln"))
    page = client.get(f"/findings/{fid}", auth=AUTH).text
    assert "What it means" not in page and "fixed in 2.32.4" in page


def test_my_codes_findings_show_their_rules_details(client):
    now = utcnow()
    with db.SessionLocal() as session:
        t = Target(name="mine", profile="owned", source="https://github.com/dev/mine.git")
        session.add(t)
        session.flush()
        scan = Scan(target_id=t.id, status="done", score=80, verdict="B", complete=True,
                    finished_at=now)  # fmt: skip
        session.add(scan)
        session.flush()
        semgrep = RawFinding("semgrep", "bad-host", "Bad host", "medium",
                             message="Binds every interface.", file="app.py", line=4,
                             evidence="run(host='0.0.0.0')",
                             details={"about": "Bind to 127.0.0.1 unless every interface is meant.",
                                      "url": "https://semgrep.dev/r/bad-host"})  # fmt: skip
        osv = RawFinding("osv-scanner", "GHSA-2xpw-w6gg-jr37", "urllib3 leaks", "high",
                         message="Package 'urllib3@1.0.0' is vulnerable to 'GHSA-2xpw-w6gg-jr37'.",
                         file="uv.lock",
                         vulns={"package": "urllib3",
                                "groups": [["GHSA-2XPW-W6GG-JR37", "CVE-2025-66471"]]},
                         details={"url": "https://osv.dev/vulnerability/GHSA-2xpw-w6gg-jr37"})
        findings.reconcile(session, t, scan, [ScannerRun("semgrep", "ok", findings=[semgrep]),
                                              ScannerRun("osv-scanner", "ok", findings=[osv])], now)
        session.commit()
        ids = {f.scanner: f.id for f in session.scalars(select(Finding))}
    page = client.get(f"/findings/{ids['semgrep']}", auth=AUTH).text
    assert ('<dt>About the rule</dt><dd class="about">Bind to 127.0.0.1 unless every interface '
            "is meant.</dd>") in page  # fmt: skip
    assert ">semgrep's page for bad-host</a>" in page and "What semgrep reported" in page
    page = client.get(f"/findings/{ids['osv-scanner']}", auth=AUTH).text
    assert 'href="https://osv.dev/vulnerability/GHSA-2XPW-W6GG-JR37"' in page
    assert "osv-scanner's page for" not in page  # the same page as the bug's own link
