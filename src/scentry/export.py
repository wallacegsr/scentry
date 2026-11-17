"""Results out of Scentry, for other tools and for people.

- JSON: one target or everything, with findings, suppressions, scans and Barkley's
  reports. Its layout carries a "format" version; fields may be added, never renamed.
- SARIF 2.1.0: one target's open and suppressed findings, for GitHub code scanning,
  DefectDojo and other tools that import it.
- CSV: every finding, for a spreadsheet.

Text in findings comes from scanned code. JSON and SARIF carry it as data; CSV cells
that a spreadsheet would run as a formula are defused.
"""

from __future__ import annotations

import csv
import datetime
import io
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from scentry import __version__
from scentry.findings import issues
from scentry.models import SEVERITY_RANK, Finding, Scan, Target, utcnow

FORMAT = 1
SCANS_PER_TARGET = 20
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note",
               "info": "note"}  # fmt: skip
# GitHub code scanning sorts by this (CVSS-like, 0-10).
SECURITY_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.0",
                     "info": "0.0"}  # fmt: skip


def _iso(dt: datetime.datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "fingerprint": f.fingerprint,
        "scanner": f.scanner,
        "rule_id": f.rule_id,
        "title": f.title,
        "message": f.message,
        "severity": f.severity,
        "category": f.category,
        "file": f.file,
        "line": f.line,
        "evidence": f.evidence,
        "status": f.status,
        "first_seen_at": _iso(f.first_seen_at),
        "last_seen_at": _iso(f.last_seen_at),
        "fixed_at": _iso(f.fixed_at),
        "suppression": None if f.status != "suppressed" else {
            "reason": f.suppression_reason,
            "note": f.suppression_note,
            "by": f.suppressed_by,
            "until": _iso(f.suppressed_until),
        },
    }  # fmt: skip


def scan_dict(s: Scan, *, report: bool = True) -> dict[str, Any]:
    out = {
        "id": s.id,
        "status": s.status,
        "ref": s.ref,
        "commit_sha": s.commit_sha,
        "queued_at": _iso(s.queued_at),
        "started_at": _iso(s.started_at),
        "finished_at": _iso(s.finished_at),
        "complete": s.complete,
        "score": s.score,
        "verdict": s.verdict,
        "error": s.error,
        "scanner_runs": s.scanner_runs or [],
        "kind": s.kind,  # "recheck": advisories asked again for scan recheck_of
        "recheck_of": s.recheck_of,
        "advisories_checked_at": _iso(s.advisories_checked_at),
        "diff_from": s.diff_from,
    }
    if report:
        out["report"] = s.report  # Barkley's, for Home Assistant targets
        out["diff"] = s.diff  # Barkley's comparison with scan diff_from
    return out


def _latest_result(target: Target) -> Scan | None:
    version = target.installed_version if target.origin == "hacs" else None
    for scan in target.scans:  # newest first
        if scan.status == "done" and scan.verdict and (version is None or scan.ref == version):
            return scan
    return None


def target_dict(session: Session, target: Target, *, scans: int = SCANS_PER_TARGET,
                reports: bool = True) -> dict[str, Any]:  # fmt: skip
    found = session.scalars(select(Finding).where(Finding.target_id == target.id)).all()
    found = sorted(found, key=lambda f: (f.status != "open", SEVERITY_RANK.get(f.severity, 9),
                                         f.scanner, f.file or ""))  # fmt: skip
    latest = _latest_result(target)
    return {
        "id": target.id,
        "name": target.name,
        "profile": target.profile,
        "source": target.source,
        "ref": target.ref,
        "origin": target.origin,
        "hacs_kind": target.hacs_kind,
        "installed_version": target.installed_version,
        "available_version": target.available_version,
        "uninstalled_at": _iso(target.hacs_removed_at),
        "interval_hours": target.interval_hours,
        "enabled": target.enabled,
        # This target's own notification settings; null = the notifier's default.
        "notify": {"muted": target.notify_muted, "score_below": target.notify_score_below,
                   "min_severity": target.notify_min_severity,
                   "clean_updates": target.notify_clean_updates,
                   "failures": target.notify_failures},  # fmt: skip
        "result": scan_dict(latest, report=reports) if latest else None,
        # What the grade counts (my code): open findings folded into problems.
        "grade_issues": [
            {"severity": i.severity, "scanner": i.scanner, "rule_id": i.rule_id,
             "title": i.title, "places": i.count, "also": i.also, "deduction": i.deduction}
            for i in issues([f for f in found if f.status == "open"])
        ] if target.profile == "owned" else None,
        "findings": [finding_dict(f) for f in found],
        "scans": [scan_dict(s, report=reports) for s in target.scans[:scans]],
    }


def _envelope(**content) -> dict[str, Any]:
    return {"tool": "scentry", "tool_version": __version__, "format": FORMAT,
            "exported_at": _iso(utcnow()), **content}  # fmt: skip


def export_target(session: Session, target: Target) -> dict[str, Any]:
    return _envelope(target=target_dict(session, target))


def export_all(session: Session) -> dict[str, Any]:
    """Every target with its findings and current result (and that result's report); the
    scan history is in each target's own export."""
    targets = session.scalars(select(Target).order_by(Target.id)).all()
    return _envelope(targets=[target_dict(session, t, scans=0) for t in targets])


def sarif(session: Session, target: Target) -> dict[str, Any]:
    """Open and suppressed findings (suppressions marked as such); fixed ones are left out."""
    found = session.scalars(
        select(Finding).where(Finding.target_id == target.id,
                              Finding.status.in_(("open", "suppressed")))
        .order_by(Finding.id)
    ).all()  # fmt: skip
    rules: dict[str, dict] = {}
    results = []
    for f in found:
        rule = f"{f.scanner}/{f.rule_id}"
        rules.setdefault(rule, {
            "id": rule,
            "name": f.rule_id,
            "shortDescription": {"text": f.title},
            "properties": {"scanner": f.scanner, "category": f.category,
                           "security-severity": SECURITY_SEVERITY.get(f.severity, "5.0")},
        })  # fmt: skip
        result: dict[str, Any] = {
            "ruleId": rule,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message or f.title},
            "partialFingerprints": {"scentry/v1": f.fingerprint},
            "properties": {"severity": f.severity, "scanner": f.scanner,
                           "first_seen_at": _iso(f.first_seen_at)},
        }  # fmt: skip
        if f.file:
            location: dict[str, Any] = {"artifactLocation": {"uri": f.file}}
            if f.line and f.line > 0:
                location["region"] = {"startLine": f.line}
                if f.evidence:
                    location["region"]["snippet"] = {"text": f.evidence}
            result["locations"] = [{"physicalLocation": location}]
        if f.status == "suppressed":
            result["suppressions"] = [{
                "kind": "external", "status": "accepted",
                "justification": f"{f.suppression_reason}: {f.suppression_note}",
            }]  # fmt: skip
        results.append(result)
    run: dict[str, Any] = {
        "tool": {"driver": {"name": "Scentry", "version": __version__,
                            "informationUri": "https://github.com/SeriesOfTubez/ha-barkley",
                            "rules": list(rules.values())}},
        "results": results,
        "properties": {"target": target.name, "source": target.source},
    }  # fmt: skip
    latest = _latest_result(target)
    if target.profile == "owned" and latest and latest.commit_sha:
        run["versionControlProvenance"] = [{"repositoryUri": target.source,
                                            "revisionId": latest.commit_sha}]  # fmt: skip
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [run]}  # fmt: skip


CSV_COLUMNS = ("target", "profile", "source", "scanner", "rule_id", "severity", "title",
               "file", "line", "status", "first_seen_at", "last_seen_at", "fixed_at",
               "suppression_reason", "suppression_note", "suppressed_until", "message")  # fmt: skip


def _cell(value: object) -> str:
    """A spreadsheet runs a cell starting with = + - @ (or a tab/CR) as a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def findings_csv(session: Session, status: str | None = None) -> str:
    q = select(Finding, Target).join(Target, Target.id == Finding.target_id)
    if status:
        q = q.where(Finding.status == status)
    rows = sorted(
        session.execute(q).all(),
        key=lambda r: (r[1].name.lower(), SEVERITY_RANK.get(r[0].severity, 9)),
    )
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for f, t in rows:
        writer.writerow([_cell(v) for v in (
            t.name, t.profile, t.source, f.scanner, f.rule_id, f.severity, f.title, f.file,
            f.line, f.status, _iso(f.first_seen_at), _iso(f.last_seen_at), _iso(f.fixed_at),
            f.suppression_reason, f.suppression_note, _iso(f.suppressed_until), f.message,
        )])  # fmt: skip
    return out.getvalue()


def filename(name: str, ext: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.")[:60] or "target"
    return f"scentry-{slug}-{utcnow():%Y%m%d}.{ext}"
