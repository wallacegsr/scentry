"""One vulnerability reported under different ids, or by two scanners, counts once."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from scentry import db, findings, notify, pipeline, sarif, worker
from scentry.config import Settings
from scentry.models import Finding, Target
from scentry.scanners.barkley import findings_of
from scentry.scanners.base import RawFinding, Scanner, ScannerRun


@pytest.fixture
def settings(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    return Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'v.db'}",
                    work_dir=str(work), allow_local_paths=True, admin_password="pw")  # fmt: skip


@pytest.fixture
def session(settings):
    db.configure(settings.database_url)
    with db.SessionLocal() as s:
        yield s


# What osv-scanner 2 writes: each vulnerability is a rule whose deprecatedIds are its
# aliases; the file is absolute; and every result comes twice.
def osv_sarif(tree, *vulns):
    rules, results = [], []
    for i, (pkg, ids, score) in enumerate(vulns):
        rules.append({"id": ids[0], "deprecatedIds": list(ids),
                      "shortDescription": {"text": f"{ids[0]}: something in {pkg}"},
                      "properties": {"security-severity": score}})
        also = ", ".join(f"'{x}'" for x in ids[1:])
        result = {"ruleId": ids[0], "ruleIndex": i, "level": "warning",
                  "message": {"text": f"Package '{pkg}@1.0.0' is vulnerable to '{ids[0]}' "
                                      f"(also known as {also})."},
                  "locations": [{"physicalLocation": {"artifactLocation": {
                      "uri": f"file://{tree.resolve().as_posix()}/requirements.txt"}}}],
                  "partialFingerprints": {"primaryLocationLineHash": f"h{i}"}}
        results += [result, dict(result)]
    return {"runs": [{"tool": {"driver": {"rules": rules}}, "results": results}]}


def barkley_dep(pkg, *advisories, severity="medium"):
    """Barkley's report form: one finding per package, its advisories with aliases."""
    return {"rule_id": "dep-vuln", "title": "Dependency with known vulnerabilities",
            "severity": severity, "category": "dependency", "file": "requirements.txt",
            "evidence": f"{pkg}@1.0.0 (PyPI): " + ", ".join(a[0] for a in advisories),
            "dependency": {"package": pkg, "advisories": [
                {"id": a[0], "aliases": list(a[1:])} for a in advisories]}}  # fmt: skip


class Fixed(Scanner):
    executable = "python"

    def __init__(self, name, found):
        self.name, self.found = name, found

    def run(self, ctx):
        return ScannerRun(self.name, "ok", findings=list(self.found))


def scan(session, settings, target, *scanners):
    worker.enqueue(session, target)
    s = worker.claim(session)
    pipeline.run_scan(session, s, settings, list(scanners))
    return s


@pytest.fixture
def target(session, tmp_path):
    (tmp_path / "repo").mkdir()
    t = Target(name="repo", profile="owned", source=str(tmp_path / "repo"))
    session.add(t)
    session.commit()
    return t


def test_osv_sarif_paths_aliases_and_repeats(tmp_path):
    tree = tmp_path / "scan-x1y2" / "tree"
    tree.mkdir(parents=True)
    doc = osv_sarif(tree, ("urllib3", ("CVE-2025-66471", "PYSEC-2026-1994",
                                       "GHSA-2xpw-w6gg-jr37"), "8.9"))  # fmt: skip
    a, b = sarif.parse(doc, "osv-scanner", tree)
    # Relative to the tree: the random work directory isn't part of the fingerprint.
    assert a.file == "requirements.txt"
    assert findings.fingerprint(a) == findings.fingerprint(b)
    assert a.vulns == {"package": "urllib3", "groups": [
        ["CVE-2025-66471", "PYSEC-2026-1994", "GHSA-2XPW-W6GG-JR37"]]}  # fmt: skip
    assert a.severity == "high"

    plain = {"runs": [{"results": [{"ruleId": "python.lang.eval", "message": {"text": "x"}}]}]}
    assert sarif.parse(plain, "semgrep", tree)[0].vulns is None
    assert sarif.vulns(["not-an-advisory"]) is None
    assert sarif.vulns(["GHSA-2xpw-w6gg-jr37", "bad id with spaces"])["groups"] == [
        ["GHSA-2XPW-W6GG-JR37"]]  # fmt: skip


def test_osv_findings_keep_their_fingerprint_from_scan_to_scan(tmp_path, settings, monkeypatch):
    import json

    from scentry.proc import Result
    from scentry.scanners.base import ScanContext
    from scentry.scanners.tools import OsvScanner

    def fake_run(cmd, cwd, **kw):
        doc = osv_sarif(cwd, ("paramiko", ("CVE-2023-48795", "GHSA-45x7-px36-x8w8"), "5.9"))
        for r in doc["runs"][0]["results"]:  # computed from the absolute path, as osv does
            r["partialFingerprints"]["primaryLocationLineHash"] = str(hash(str(cwd)))
        out = cmd[cmd.index("--output") + 1]
        with open(out, "w", encoding="utf-8") as fh:  # noqa: PTH123
            json.dump(doc, fh)
        return Result(1, "", "")

    monkeypatch.setattr("scentry.scanners.base.proc.run", fake_run)
    prints = set()
    for name in ("scan-aaa", "scan-bbb"):
        tree = tmp_path / name / "tree"
        tree.mkdir(parents=True)
        run = OsvScanner().run(ScanContext(settings, "owned", "x", None, tmp_path, tree))
        prints |= {findings.fingerprint(f) for f in run.findings}
    assert len(prints) == 1


def test_barkley_dependency_findings_carry_their_advisories():
    (f,) = findings_of({"findings": [barkley_dep(
        "urllib3", ("GHSA-2xpw-w6gg-jr37", "CVE-2025-66471"), ("GHSA-34jh-p97f-mpxf",))]})
    assert f.vulns == {"package": "urllib3", "groups": [
        ["GHSA-2XPW-W6GG-JR37", "CVE-2025-66471"], ["GHSA-34JH-P97F-MPXF"]]}  # fmt: skip
    (plain,) = findings_of({"findings": [{"rule_id": "ha-token-exfil", "severity": "high"}]})
    assert plain.vulns is None


def test_a_repeated_result_is_one_finding(session, settings, target, tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    doc = osv_sarif(tree, ("idna", ("CVE-2026-45409", "GHSA-65pc-fj4g-8rjx"), "7.5"))
    raw = sarif.parse(doc, "osv-scanner", tree)
    assert len(raw) == 2
    scan(session, settings, target, Fixed("osv-scanner", raw))
    assert len(session.scalars(select(Finding)).all()) == 1


def osv(pkg, *ids, severity="high"):
    return RawFinding("osv-scanner", ids[0], f"{ids[0]} in {pkg}", severity, file="req.txt",
                      fingerprint_hint=ids[0],
                      vulns=sarif.vulns(list(ids), pkg))  # fmt: skip


def test_two_scanners_one_vulnerability(session, settings, target):
    from_osv = [osv("urllib3", "CVE-2025-66471", "GHSA-2xpw-w6gg-jr37"),
                osv("Jinja2", "CVE-2019-10906", "PYSEC-2019-217")]  # fmt: skip
    from_barkley = findings_of({"findings": [
        # Both covered by osv-scanner, under their GHSA and PYSEC names.
        barkley_dep("urllib3", ("GHSA-2xpw-w6gg-jr37",)),
        barkley_dep("jinja2", ("PYSEC-2019-217", "CVE-2019-10906")),
        # One covered, one osv-scanner didn't report: stays its own finding.
        barkley_dep("idna", ("GHSA-65pc-fj4g-8rjx",), ("GHSA-aaaa-bbbb-cccc",)),
    ]})
    first = scan(session, settings, target, Fixed("osv-scanner", from_osv),
                 Fixed("barkley", from_barkley))  # fmt: skip
    rows = {(f.scanner, (f.vulns or {}).get("package")): f
            for f in session.scalars(select(Finding))}  # fmt: skip
    cve_urllib3 = rows[("osv-scanner", "urllib3")]
    assert rows[("barkley", "urllib3")].same_as == cve_urllib3.id
    assert rows[("barkley", "jinja2")].same_as == rows[("osv-scanner", "Jinja2")].id
    assert rows[("barkley", "idna")].same_as is None

    open_now = session.scalars(select(Finding).where(Finding.status == "open")).all()
    issues = {(i.scanner, i.rule_id): i for i in findings.issues(open_now)}
    assert set(issues) == {("osv-scanner", "CVE-2025-66471"), ("osv-scanner", "CVE-2019-10906"),
                           ("barkley", "dep-vuln")}  # fmt: skip
    assert issues[("barkley", "dep-vuln")].count == 1  # idna only
    assert issues[("osv-scanner", "CVE-2025-66471")].also == ["barkley: dep-vuln"]

    # New findings are announced once: the twins stay out of the message.
    item = notify.evaluate(session, first, settings.model_copy(
        update={"notify_min_severity": "medium"}))  # fmt: skip
    assert "3 new findings" in item.text

    # Suppressing the vulnerability under one name keeps its twin out of the grade too.
    cve_urllib3.status = "suppressed"
    session.commit()
    open_now = session.scalars(select(Finding).where(Finding.status == "open")).all()
    keys = {(i.scanner, i.rule_id) for i in findings.issues(open_now)}
    assert ("osv-scanner", "CVE-2025-66471") not in keys and len(keys) == 2

    # Fixed where osv-scanner looked (it's gone from its results): Barkley's report of it
    # is a finding of its own again.
    cve_urllib3.status = "open"
    session.commit()
    scan(session, settings, target, Fixed("osv-scanner", from_osv[1:]),
         Fixed("barkley", from_barkley))  # fmt: skip
    session.expire_all()
    assert session.get(Finding, cve_urllib3.id).status == "fixed"
    assert rows[("barkley", "urllib3")].same_as is None


def test_same_id_in_another_package_is_another_vulnerability(session, settings, target):
    scan(session, settings, target,
         Fixed("osv-scanner", [osv("requests", "CVE-2023-32681", "GHSA-j8r2-6x86-q33q")]),
         Fixed("barkley", findings_of({"findings": [
             barkley_dep("pip", ("GHSA-j8r2-6x86-q33q",))]})))  # fmt: skip
    assert all(f.same_as is None for f in session.scalars(select(Finding)))


def test_one_scanner_two_names_for_one_vulnerability(session, settings, target):
    # Two rules for one vulnerability (its records weren't linked), joined by an alias
    # list a third report gives.
    scan(session, settings, target, Fixed("osv-scanner", [
        osv("idna", "PYSEC-2026-215"), osv("idna", "GHSA-65pc-fj4g-8rjx"),
        osv("idna", "CVE-2026-45409", "PYSEC-2026-215", "GHSA-65pc-fj4g-8rjx")]))
    rows = session.scalars(select(Finding).order_by(Finding.id)).all()
    kept = [f.rule_id for f in rows if f.same_as is None]
    assert kept == ["PYSEC-2026-215"] and {f.same_as for f in rows[1:]} == {rows[0].id}
    issues = findings.issues(rows)
    assert len(issues) == 1 and sorted(issues[0].also) == [
        "osv-scanner: CVE-2026-45409", "osv-scanner: GHSA-65pc-fj4g-8rjx"]  # fmt: skip


def test_target_page_says_which_finding_it_repeats(tmp_path):
    from fastapi.testclient import TestClient

    from scentry.web.app import create_app

    s = Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'w.db'}",
                 admin_password="pw")  # fmt: skip
    client = TestClient(create_app(s))
    with db.SessionLocal() as session:
        t = Target(name="repo", profile="owned", source="https://github.com/me/repo.git")
        session.add(t)
        session.flush()
        held = Finding(target_id=t.id, fingerprint="a", scanner="osv-scanner",
                       rule_id="CVE-2025-66471", title="urllib3", severity="high",
                       vulns={"package": "urllib3",
                              "groups": [["CVE-2025-66471", "GHSA-2XPW-W6GG-JR37"]]})  # fmt: skip
        session.add(held)
        session.flush()
        session.add(Finding(target_id=t.id, fingerprint="b", scanner="barkley",
                            rule_id="dep-vuln", title="Dependency", severity="medium",
                            same_as=held.id))  # fmt: skip
        session.commit()
        tid, held_id = t.id, held.id
        twin_id = session.scalar(select(Finding.id).where(Finding.same_as == held_id))
    assert "same vulnerability" in client.get(f"/targets/{tid}", auth=("admin", "pw")).text
    page = client.get(f"/findings/{twin_id}", auth=("admin", "pw")).text
    assert "Already reported by osv-scanner as" in page and f"/findings/{held_id}" in page
    page = client.get(f"/findings/{held_id}", auth=("admin", "pw")).text
    assert "urllib3: CVE-2025-66471 = GHSA-2XPW-W6GG-JR37" in page
    exported = client.get(f"/targets/{tid}/export.json", auth=("admin", "pw")).json()
    same = {f["rule_id"]: f["same_as"] for f in exported["target"]["findings"]}
    assert same == {"CVE-2025-66471": None, "dep-vuln": held_id}
