from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest
from sqlalchemy import select

from scentry import acquire, db, findings, pipeline, sarif, worker
from scentry.config import Settings
from scentry.models import Finding, RuleSuppression, Scan, Target, utcnow
from scentry.scanners.barkley import Barkley, is_ha_repo
from scentry.scanners.base import RawFinding, ScanContext, Scanner, ScannerRun


@pytest.fixture
def settings(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        work_dir=str(work),
        allow_local_paths=True,
        admin_password="pw",
    )


@pytest.fixture
def session(settings):
    db.configure(settings.database_url)
    with db.SessionLocal() as s:
        yield s


def raw(rule="r1", file="a.py", evidence="eval(x)", severity="high", scanner="fake", line=3):
    return RawFinding(scanner=scanner, rule_id=rule, title=rule, severity=severity,
                      file=file, line=line, evidence=evidence)  # fmt: skip


class Fake(Scanner):
    name = executable = "python"  # always on PATH

    def __init__(self, results, name="fake"):
        self.results, self.name = results, name

    def run(self, ctx):
        return ScannerRun(self.name, "ok", findings=list(self.results))


# --- SARIF ---------------------------------------------------------------------------

SARIF = {
    "runs": [{
        "tool": {"driver": {"rules": [
            {"id": "sqli", "shortDescription": {"text": "SQL injection"},
             "properties": {"security-severity": "9.1"}},
            {"id": "weak", "defaultConfiguration": {"level": "note"}},
        ]}},
        "results": [
            {"ruleId": "sqli", "message": {"text": "tainted\x07 query"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "app/db.py"},
                 "region": {"startLine": 2, "snippet": {"text": "cur.execute(q)"}}}}],
             "partialFingerprints": {"matchBasedId/v1": "abc", "other": "requires login"}},
            {"ruleIndex": 1, "message": {"text": "weak hash"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "app/h.py"}, "region": {"startLine": 1}}}]},
            {"ruleId": "nolevel", "message": {"text": "x"}},
        ],
    }]
}  # fmt: skip


def test_sarif_parse(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "h.py").write_text("md5(data)\n")
    a, b, c = sarif.parse(SARIF, "semgrep", tmp_path)
    assert (a.rule_id, a.title, a.severity, a.file, a.line) == (
        "sqli", "SQL injection", "critical", "app/db.py", 2)  # fmt: skip
    assert a.message == "tainted query"  # control characters stripped
    assert a.fingerprint_hint == "matchBasedId/v1=abc"
    assert (b.rule_id, b.severity, b.evidence) == ("weak", "low", "md5(data)")
    assert (c.severity, c.file) == ("medium", None)


def test_sarif_floor_and_path_escape(tmp_path):
    doc = {"runs": [{"results": [{"ruleId": "key", "level": "note", "locations": [
        {"physicalLocation": {"artifactLocation": {"uri": "../outside.txt"},
                              "region": {"startLine": 1}}}]}]}]}  # fmt: skip
    (tmp_path / "outside.txt").write_text("secret\n")
    tree = tmp_path / "tree"
    tree.mkdir()
    (f,) = sarif.parse(doc, "gitleaks", tree, floor="high")
    assert f.severity == "high"
    assert f.evidence is None  # a path outside the tree is never read


def test_hidden_characters_in_evidence_are_marked():
    rlo, lri, pdi = chr(0x202E), chr(0x2066), chr(0x2069)
    assert sarif.evidence(f'return "{lri}" + x + "{pdi}"') == 'return "<U+2066>" + x + "<U+2069>"'
    # A CRLF is a line end; a lone CR or an escape code is a hidden character.
    assert sarif.evidence("x\x1b[2Jy\r\nz\rw") == "x<U+001B>[2Jy\nz<U+000D>w"
    # Code that writes the character as an escape reads differently from the character.
    written = r'ContainsAny(name, "\u202e")'
    assert sarif.evidence(written) == written
    assert sarif.evidence("a" * 497 + rlo) == "a" * 497 + "…"  # never half a mark
    assert sarif.evidence(f"{rlo}  ") == "<U+202E>" and sarif.evidence(None) == ""
    # Without its marks: what clean() kept before, so fingerprints don't move.
    for text in (f'if strings.ContainsAny(name, "{rlo}{lri}") {{', "x\x1b[2Jy\r\n", "<U+0041> !"):
        assert sarif.unmarked(sarif.evidence(text)) == sarif.clean(text, 500)
    before = findings.fingerprint(raw(evidence=sarif.clean(f"a{rlo}b", 500)))
    assert findings.fingerprint(raw(evidence=sarif.evidence(f"a{rlo}b"))) == before
    doc = {"runs": [{"results": [{"ruleId": "bidi", "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "a.go"}, "region": {"startLine": 1, "snippet": {
            "text": f'x := "{rlo}"'}}}}]}]}]}  # fmt: skip
    assert sarif.parse(doc, "semgrep")[0].evidence == 'x := "<U+202E>"'


def test_the_source_holds_no_hidden_characters():
    """Scentry's own files write a hidden character as an escape, never as itself: it is what
    a bidi attack hides in, and Bandit (B613) and Semgrep rightly flag it when Scentry scans
    itself. A tab, a line end and a carriage return are the only control characters."""
    root = Path(__file__).resolve().parents[1]
    files = [root / ".env.example", *root.glob("*.md"), *root.glob("*.toml"),
             *root.glob("*.yaml")]  # fmt: skip
    for folder in ("src", "tests", "docker", ".github"):
        files += [p for p in (root / folder).rglob("*")
                  if p.is_file() and "__pycache__" not in p.parts]  # fmt: skip
    found = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # an image or a font
        for n, line in enumerate(text.split(chr(10)), 1):
            hidden = [f"U+{ord(c):04X}" for c in line if ord(c) not in (9, 13)
                      and unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")]  # fmt: skip
            if hidden:
                found.append(f"{path.relative_to(root)}:{n} {' '.join(hidden)}")
    assert not found, "write these as escapes: " + ", ".join(found)


# --- fingerprints and lifecycle --------------------------------------------------------


def test_fingerprint_survives_a_moved_line():
    assert findings.fingerprint(raw(line=3)) == findings.fingerprint(raw(line=40))
    assert findings.fingerprint(raw()) != findings.fingerprint(raw(file="b.py"))
    assert findings.fingerprint(raw()) != findings.fingerprint(raw(scanner="other"))


def test_identical_matches_stay_separate(session, settings, tmp_path):
    (tmp_path / "repo").mkdir()
    target = Target(name="repo", profile="owned", source=str(tmp_path / "repo"))
    session.add(target)
    session.commit()
    twice = [raw(line=2), raw(line=3)]  # same rule, file and text
    for _ in range(2):  # and stable across rescans
        _scan(session, target, settings, [Fake(twice)])
        assert len(session.scalars(select(Finding)).all()) == 2


def _scan(session, target, settings, scanners):
    scan = worker.enqueue(session, target)
    claimed = worker.claim(session)
    assert claimed.id == scan.id
    pipeline.run_scan(session, claimed, settings, scanners)
    return claimed


def test_target_removed_during_its_scan(session, settings, tmp_path):
    """Removing a target in the portal while it is scanned must not stop the runner."""
    (tmp_path / "repo").mkdir()
    target = Target(name="repo", profile="owned", source=str(tmp_path / "repo"))
    session.add(target)
    session.commit()
    target_id = target.id

    class RemovesIt(Fake):
        def run(self, ctx):
            with db.SessionLocal() as portal:
                portal.delete(portal.get(Target, target_id))
                portal.commit()
            return super().run(ctx)

    _scan(session, target, settings, [RemovesIt([raw()])])  # doesn't raise
    assert session.scalars(select(Scan)).all() == []
    assert session.scalars(select(Finding)).all() == []


def test_lifecycle(session, settings, tmp_path):
    src = tmp_path / "repo"
    src.mkdir()
    (src / "a.py").write_text("x\n")
    (src / ".semgrepignore").write_text("*\n")
    target = Target(name="repo", profile="owned", source=str(src))
    session.add(target)
    session.commit()

    one, two = raw("r1"), raw("r2", severity="critical")
    s1 = _scan(session, target, settings, [Fake([one, two])])
    assert (s1.status, s1.complete, s1.verdict, s1.score) == ("done", True, "D", 65)
    assert not list(Path(settings.work_dir).iterdir())  # workspace removed

    # r2 goes away -> fixed; the grade follows
    s2 = _scan(session, target, settings, [Fake([one])])
    by_rule = {f.rule_id: f for f in session.scalars(select(Finding))}
    assert by_rule["r2"].status == "fixed"
    assert (s2.verdict, s2.score) == ("B", 89)  # one open high caps at 89

    # a scanner that fails fixes nothing and makes the scan incomplete
    class Broken(Fake):
        def run(self, ctx):
            raise RuntimeError("boom")

    s3 = _scan(session, target, settings, [Broken([])])
    session.refresh(by_rule["r1"])
    assert by_rule["r1"].status == "open"
    assert s3.complete is False and s3.scanner_runs[0]["state"] == "error"

    # suppressed findings stop counting, and come back when the suppression expires
    by_rule["r1"].status = "suppressed"
    by_rule["r1"].suppressed_until = utcnow() - datetime.timedelta(days=1)
    session.commit()
    s4 = _scan(session, target, settings, [Fake([one, two])])
    session.refresh(by_rule["r1"])
    session.refresh(by_rule["r2"])
    assert by_rule["r1"].status == "open"  # expired
    assert by_rule["r2"].status == "open"  # reopened
    assert s4.verdict == "D"


def test_missing_tool_is_incomplete(session, settings, tmp_path):
    src = tmp_path / "repo"
    src.mkdir()
    target = Target(name="repo", profile="owned", source=str(src))
    session.add(target)
    session.commit()

    class Missing(Fake):
        executable = "no-such-tool-xyz"

    scan = _scan(session, target, settings, [Missing([], name="missing")])
    assert scan.complete is False
    assert scan.scanner_runs[0]["state"] == "skipped"
    assert (scan.score, scan.verdict) == (89, "B")  # no findings, but never an A


def test_failed_clone_is_reported(session, settings):
    target = Target(name="x", profile="owned", source="/no/such/dir-xyz")
    session.add(target)
    session.commit()
    scan = _scan(session, target, settings, [])
    assert scan.status == "failed" and scan.error


def test_grade_caps():
    assert findings.grade([], True) == (100, "A")
    assert findings.grade([], False) == (89, "B")
    assert findings.grade([raw("c", severity="critical")], True) == (69, "D")
    mediums = [raw(f"m{i}", severity="medium") for i in range(3)]
    assert findings.grade(mediums, True) == (91, "A")
    highs = [raw(f"h{i}", severity="high") for i in range(20)]
    assert findings.grade(highs, True) == (0, "F")


def test_grade_counts_each_problem_once():
    # Thirteen unpinned actions are one thing to fix: one deduction, not thirteen.
    unpinned = [raw("unpinned-uses", file=".github/workflows/ci.yml", line=n,
                    scanner="zizmor") for n in range(10, 23)]  # fmt: skip
    assert findings.grade(unpinned, True) == (89, "B")  # one high: -10, capped at 89
    # Semgrep says the same thing about the same lines: still one problem.
    twin = [raw("mutable-action-tag", file=".github/workflows/ci.yml", line=n,
                scanner="semgrep", severity="medium") for n in range(10, 23)]  # fmt: skip
    found = findings.issues(unpinned + twin)
    assert len(found) == 1 and found[0].severity == "high"
    assert found[0].also == ["semgrep: mutable-action-tag"] and found[0].count == 13
    # A different problem that shares one of those lines stays apart.
    poison = raw("cache-poisoning", file=".github/workflows/ci.yml", line=10, scanner="zizmor")
    assert len(findings.issues(unpinned + twin + [poison])) == 2
    assert findings.grade(unpinned + twin + [poison], True) == (80, "B")


# --- queue ---------------------------------------------------------------------------


def test_queue_and_schedule(session):
    target = Target(name="t", profile="owned", source="https://example.com/a/b", interval_hours=24)
    session.add(target)
    session.commit()
    assert worker.schedule_due(session) == 1
    assert worker.schedule_due(session) == 0  # already queued
    assert worker.enqueue(session, target).id == 1  # no duplicate
    scan = worker.claim(session)
    assert scan.status == "running" and worker.claim(session) is None
    assert worker.requeue_interrupted(session) == 1
    scan = worker.claim(session)
    scan.status, scan.finished_at = "done", utcnow()
    session.commit()
    assert worker.schedule_due(session) == 0
    assert worker.schedule_due(session, utcnow() + datetime.timedelta(hours=25)) == 1
    assert session.scalar(select(Scan).where(Scan.status == "queued")) is not None


# --- fetching ------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "http://github.com/a/b", "https://user:tok@github.com/a/b", "ssh://git@github.com/a/b",
    "https://github.com/a/b --upload-pack=x", "-oProxyCommand=x", "relative/path",
])  # fmt: skip
def test_bad_sources_refused(url):
    with pytest.raises(acquire.AcquireError):
        acquire.validate_source(url, Settings(_env_file=None))


def test_refs_and_ha_repos():
    acquire.validate_ref("release/v1.2.3")
    for bad in ("--upload-pack=x", "a..b", "a b"):
        with pytest.raises(acquire.AcquireError):
            acquire.validate_ref(bad)
    assert acquire.normalize_ha_repo("https://github.com/Owner/Repo.git/") == "Owner/Repo"
    for bad in ("--ref", "a/b/c", "https://evil.example/a/b", "-x/y"):
        with pytest.raises(acquire.AcquireError):
            acquire.normalize_ha_repo(bad)


def test_token_goes_to_its_own_host_only():
    tokens = {"GitHub.com": "t0k"}
    env = acquire.auth_env("https://github.com/me/private.git", tokens)
    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
    assert "t0k" not in env["GIT_CONFIG_VALUE_0"]  # base64, not the bare token
    assert acquire.auth_env("https://github.com.evil.example/me/x.git", tokens) == {}


def test_sanitize(tmp_path, settings):
    (tmp_path / ".semgrepignore").write_text("*")
    (tmp_path / ".gitleaks.toml").write_text("")
    # Semgrep and osv-scanner also read these in any folder.
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / ".semgrepignore").write_text("*")
    (tmp_path / "a" / "osv-scanner.toml").write_text("")
    (tmp_path / "a" / "trivy.yaml").write_text("")  # only read at the top: left alone
    assert acquire.sanitize(tmp_path, settings) == [
        ".gitleaks.toml", ".semgrepignore", "a/b/.semgrepignore", "a/osv-scanner.toml"]
    assert (tmp_path / "a" / "trivy.yaml").exists()
    (tmp_path / ".semgrepignore").write_text("*")
    honoring = settings.model_copy(update={"honor_repo_ignores": True})
    assert acquire.sanitize(tmp_path, honoring) == []


# --- Barkley adapter -----------------------------------------------------------------


def test_barkley_report_mapping(tmp_path, settings, monkeypatch):
    report = {
        "schema_version": 1, "tool": {"version": "0.13.0"}, "score": 35, "complete": True,
        "verdict": {"key": "bork", "label": "BORK BORK BORK"},
        "target": {"commit_sha": "abc", "ref": "v1.0.0"},
        "findings": [{"rule_id": "ha-token-exfil", "title": "Token sent out",
                      "severity": "critical", "category": "exfil", "message": "m",
                      "file": "custom_components/x/__init__.py", "line": 9, "evidence": "e"}],
        "context": {"big": "blob"},
    }  # fmt: skip
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"], seen["env"] = cmd, kwargs.get("env")
        Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(report))
        from scentry.proc import Result
        return Result(1, "", "")  # findings -> non-zero exit must not matter

    monkeypatch.setattr("scentry.scanners.barkley.proc.run", fake_run)
    ctx = ScanContext(settings.model_copy(update={"public_github_token": "pub"}), "ha",
                      "owner/repo", "v1.0.0", tmp_path)  # fmt: skip
    run = Barkley().run(ctx)
    assert seen["cmd"][:5] == ["sniff-test", "scan", "owner/repo", "--ref", "v1.0.0"]
    assert seen["cmd"][-1] == "--json"  # no store set
    assert run.extra["barkley_id"] is None
    assert seen["env"] == {"GITHUB_TOKEN": "pub"}
    assert run.state == "ok" and run.extra["verdict"] == "BORK BORK BORK"
    assert "context" not in run.extra["report"]
    assert run.findings[0].severity == "critical"

    report["schema_version"] = 2
    assert Barkley().run(ctx).state == "error"


LIMIT_MSG = ("couldn't get a sniff: GitHub's API limit is used up (60 requests/hour without\n"
             "a token); it resets at 16:14 UTC. A GitHub token raises it to 5,000/hour")


def test_rate_limit_reset():
    from scentry.scanners.barkley import rate_limit_reset

    morning = datetime.datetime(2026, 11, 17, 16, 2)
    assert rate_limit_reset(LIMIT_MSG, morning) == datetime.datetime(2026, 11, 17, 16, 15)
    late = datetime.datetime(2026, 11, 17, 23, 50)  # 16:14 is tomorrow's
    assert rate_limit_reset(LIMIT_MSG, late) == datetime.datetime(2026, 11, 18, 16, 15)
    assert rate_limit_reset("API rate limit exceeded", morning) == morning + datetime.timedelta(
        minutes=15)  # fmt: skip
    assert rate_limit_reset("repository not found", morning) is None


def test_github_limit_holds_the_queue_instead_of_failing(session, settings, tmp_path,
                                                         monkeypatch):  # fmt: skip
    from scentry.proc import Result

    monkeypatch.setattr("scentry.scanners.barkley.proc.run",
                        lambda cmd, **kw: Result(1, "", LIMIT_MSG))  # fmt: skip
    monkeypatch.setattr(Barkley, "executable", "python")  # sniff-test needn't be installed
    first, second = (Target(name=n, profile="ha", source=f"o/{n}") for n in ("a", "b"))
    session.add_all([first, second])
    session.commit()
    one = worker.enqueue(session, first, "1.0")
    two = worker.enqueue(session, second, "2.0")
    claimed = worker.claim(session)
    pipeline.run_scan(session, claimed, settings, [Barkley()])

    assert (one.status, one.finished_at, one.score) == ("queued", None, None)
    session.refresh(two)  # held by a bulk update
    assert one.not_before is not None and one.not_before == two.not_before
    assert worker.claim(session) is None  # nothing runs before the reset
    assert worker.claim(session, one.not_before).id == one.id


def test_is_ha_repo(tmp_path):
    assert not is_ha_repo(tmp_path)
    (tmp_path / "custom_components" / "x").mkdir(parents=True)
    (tmp_path / "custom_components" / "x" / "manifest.json").write_text("{}")
    assert is_ha_repo(tmp_path)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc only")
def test_scanners_cant_read_the_runners_environment():
    """A scanner runs as the runner's user: it mustn't be able to read the runner's
    environment (tokens, database password) from /proc."""
    peek = ("import sys; p = sys.argv[1]\n"
            "try: print(b'TOKEN=t0k' in open(f'/proc/{p}/environ', 'rb').read())\n"
            "except OSError: print('denied')")  # fmt: skip
    runner = ("import os, subprocess, sys\n"
              "from scentry import proc\n"
              "def look(): return subprocess.run([sys.executable, '-I', '-c', sys.argv[1],"
              " str(os.getpid())], capture_output=True, text=True).stdout.strip()\n"
              "before = look(); ok = proc.keep_secrets_from_children(); print(before, ok, look())")
    out = subprocess.run([sys.executable, "-c", runner, peek], capture_output=True, text=True,
                         env={**os.environ, "TOKEN": "t0k"}, check=True).stdout.split()
    assert out == ["True", "True", "denied"]


def test_scanners_keep_temporary_files_in_the_scans_folder(session, settings, tmp_path):
    """Not in the system's /tmp, which is small: in the scan's work folder, which is
    sized for them (SCENTRY_WORK_SIZE) and removed with the scan."""
    from scentry import proc

    seen = {}

    class Temp(Fake):
        def run(self, ctx):
            env = proc.clean_env()  # what a scanner program is started with
            seen.update(tmp=env["TMPDIR"], temp=env["TEMP"], there=Path(env["TMPDIR"]).is_dir())
            return ScannerRun(self.name, "ok")

    (tmp_path / "repo").mkdir()
    target = Target(name="repo", profile="owned", source=str(tmp_path / "repo"))
    session.add(target)
    session.commit()
    _scan(session, target, settings, [Temp([])])
    tmp = Path(seen["tmp"])
    assert seen["there"] and seen["temp"] == seen["tmp"]
    assert tmp.parent.parent == Path(settings.work_dir) and not tmp.exists()
    assert proc.clean_env().get("TMPDIR") != seen["tmp"]  # only while the scan runs


def test_barkley_names_its_checks_that_didnt_finish(session, settings, monkeypatch, caplog):
    from fastapi.testclient import TestClient

    from scentry.proc import Result
    from scentry.web.app import create_app

    report = {
        "schema_version": 1, "tool": {"version": "0.13.0"}, "score": 0, "complete": False,
        "verdict": {"label": "BORK BORK BORK"}, "target": {"ref": "v3.45.1"}, "findings": [],
        "analyzers": [
            {"name": "semgrep", "state": "ok", "detail": "160 files scanned"},
            {"name": "npm", "state": "not_applicable", "detail": "no package.json"},
            {"name": "guarddog", "state": "error",
             "detail": "x.whl: No usable temporary directory found in ['/tmp']\x07"},
        ],
    }  # fmt: skip

    def fake_run(cmd, **kwargs):
        Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(report))
        return Result(0, "", "")

    monkeypatch.setattr("scentry.scanners.barkley.proc.run", fake_run)
    monkeypatch.setattr(Barkley, "executable", "python")
    target = Target(name="Agent", profile="ha", source="o/agent")
    session.add(target)
    session.commit()
    scan = _scan(session, target, settings, [Barkley()])

    unfinished = "guarddog (x.whl: No usable temporary directory found in ['/tmp'])"
    (run,) = scan.scanner_runs
    assert run["state"] == "ok" and run["unfinished"] == [unfinished]
    assert run["detail"] == f"sniff-test 0.13.0; didn't finish: {unfinished}"
    assert not scan.complete and scan.verdict == "BORK BORK BORK"
    assert "barkley ok: sniff-test 0.13.0; didn't finish: guarddog" in caplog.text

    page = TestClient(create_app(settings)).get(f"/scans/{scan.id}", auth=("admin", "pw")).text
    assert "Incomplete: what didn&#39;t finish" not in page  # template text isn't escaped
    assert "Incomplete: what didn't finish is below" in page
    assert ("<strong>barkley</strong> › guarddog (x.whl: No usable temporary directory "
            "found in [&#39;/tmp&#39;])") in page
    assert '<span class="pill warn">incomplete</span>' in page


# --- a rule suppressed in some files ----------------------------------------------------


def test_path_patterns():
    tidy = findings.path_pattern
    assert tidy(" ./tests/ ") == "tests/" and tidy("/a.py") == "a.py"
    assert tidy("src" + chr(92) + "web" + chr(92)) == "src/web/"  # written the Windows way
    for blanket in ("", "  ", "*", "**", "**/", "**/*", "/", "./", ".", "a//b", "x" * 501):
        assert tidy(blanket) is None, blanket

    def matches(pattern, *paths):
        return [findings.path_matches(pattern, p) for p in paths]

    # A folder holds what's under it, at any depth; nothing outside it.
    assert matches("tests/", "tests/a.py", "tests/x/y.py", "src/tests/a.py", "testsx/a.py",
                   "tests") == [True, True, False, False, False]  # fmt: skip
    assert matches("**/tests/", "tests/a.py", "src/tests/a.py") == [True, True]
    # * stays within a name, ** crosses folders (or none).
    assert matches("src/**/*.html", "src/a.html", "src/x/y/a.html", "src/a.htm",
                   "x/src/a.html") == [True, True, False, False]  # fmt: skip
    assert matches("*.md", "README.md", "docs/a.md") == [True, False]
    assert matches("a?.py", "a1.py", "a/.py") == [True, False]
    assert matches("a+b(c).py", "a+b(c).py", "aab(c).py") == [True, False]  # not a regex
    assert matches("tests/a.py", "tests/a.py", "tests/a.pyc") == [True, False]
    assert findings.path_matches("tests/", None) is False


def test_a_rule_suppression_takes_in_what_scans_open_there(session):
    target = Target(name="repo", profile="owned", source="/nowhere")
    session.add(target)
    session.flush()

    def scan_with(*found):
        scan = Scan(target_id=target.id, status="done")
        session.add(scan)
        session.flush()
        findings.reconcile(session, target, scan, [ScannerRun("fake", "ok", findings=[
            raw(rule, file, evidence=f"x = {file}") for rule, file in found])])  # fmt: skip
        session.commit()
        return {(f.rule_id, f.file): f for f in session.scalars(select(Finding))}

    scan_with(("r1", "tests/a.py"), ("r1", "tests/old.py"))
    scan_with(("r1", "tests/a.py"))  # tests/old.py is fixed
    later = utcnow() + datetime.timedelta(days=30)
    rule = RuleSuppression(target_id=target.id, scanner="fake", rule_id="r1", pattern="tests/",
                           reason="false_positive", note="test fixtures", created_by="admin",
                           until=later)  # fmt: skip
    session.add(rule)
    session.commit()

    now = scan_with(("r1", "tests/a.py"), ("r1", "tests/old.py"), ("r1", "tests/b/c.py"),
                    ("r1", "src/a.py"), ("r2", "tests/d.py"))  # fmt: skip
    for key in (("r1", "tests/old.py"), ("r1", "tests/b/c.py")):  # back, and new
        f = now[key]
        assert (f.status, f.rule_suppression_id, f.suppression_reason, f.suppression_note,
                f.suppressed_by, f.suppressed_until) == (
            "suppressed", rule.id, "false_positive", "test fixtures", "admin", later)  # fmt: skip
    # Open before the scan (reopened by hand, say): left open. Another file, another rule.
    assert [now[k].status for k in (("r1", "tests/a.py"), ("r1", "src/a.py"),
                                    ("r2", "tests/d.py"))] == ["open"] * 3  # fmt: skip

    # An expired rule suppression takes in nothing new; its findings come back for review.
    rule.until = utcnow() - datetime.timedelta(minutes=1)
    for key in (("r1", "tests/old.py"), ("r1", "tests/b/c.py")):
        now[key].suppressed_until = rule.until
    session.commit()
    now = scan_with(("r1", "tests/old.py"), ("r1", "tests/b/c.py"), ("r1", "tests/e.py"))
    for key in (("r1", "tests/old.py"), ("r1", "tests/b/c.py"), ("r1", "tests/e.py")):
        assert (now[key].status, now[key].rule_suppression_id) == ("open", None)
