"""Results out of Scentry, for other tools and for people.

- JSON: one target or everything, with findings, suppressions, scans and Barkley's
  reports. Its layout carries a "format" version; fields may be added, never renamed.
- SARIF 2.1.0: one target's open and suppressed findings, for GitHub code scanning,
  DefectDojo and other tools that import it.
- CSV: every finding, for a spreadsheet.
- Markdown: one finding, for a GitHub issue, a security advisory or a message.

Text in findings comes from scanned code. JSON and SARIF carry it as data; CSV cells
that a spreadsheet would run as a formula are defused; in Markdown it can't add
formatting, links or @mentions.
"""

from __future__ import annotations

import csv
import datetime
import io
import re
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote, urlencode

from sqlalchemy import select
from sqlalchemy.orm import Session

from scentry import __version__
from scentry.findings import issues
from scentry.models import SEVERITY_RANK, AiNote, Finding, Scan, Target, utcnow

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
        "vulnerabilities": f.vulns,  # {"package", "groups": [[id, alias...], ...]}
        "same_as": f.same_as,  # repeats this finding's vulnerabilities: counted there
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
        "watch_commits": target.watch_commits if target.profile == "owned" else None,
        "head_sha": target.head_sha,  # the branch's commit when last asked
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


def export_all(session: Session, only: set[int] | None = None) -> dict[str, Any]:
    """Every target (or those in `only`) with its findings and current result (and that
    result's report); the scan history is in each target's own export."""
    targets = session.scalars(select(Target).order_by(Target.id)).all()
    return _envelope(targets=[target_dict(session, t, scans=0) for t in targets
                              if only is None or t.id in only])


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


def findings_csv(session: Session, status: str | None = None,
                 only: set[int] | None = None) -> str:
    """Findings as a spreadsheet: all, or of one status; of every target, or of `only`."""
    q = select(Finding, Target).join(Target, Target.id == Finding.target_id)
    if status:
        q = q.where(Finding.status == status)
    if only is not None:
        q = q.where(Target.id.in_(only))
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


# --- Markdown: one finding, for a GitHub issue or a message ---------------------------

ISSUE_URL_MAX = 8000  # GitHub turns much longer addresses away
SECRET_SCANNERS = {"gitleaks"}  # their excerpt is a secret's line: never put in a report
REAL = {"likely": "Looks real", "unlikely": "Probably harmless here", "unclear": "Can't tell"}
LANGUAGES = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".ts": "typescript",
             ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".sh": "bash", ".toml": "toml",
             ".html": "html", ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
             ".java": "java", ".tf": "hcl"}  # fmt: skip
_GITHUB_URL = re.compile(r"^https://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?/?$")
_REPO = re.compile(r"^[\w.-]+/[\w.-]+$")
_GHSA = re.compile(r"^GHSA(-[a-z0-9]{4}){3}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_MARKUP = re.compile(r"([\\`*_\[\]<>|~&])")
WORD_JOINER = "\u2060"  # invisible; keeps GitHub from reading @name or #12 as a reference


def github_repo(target: Target) -> str | None:
    """owner/repo when the target's code is on GitHub."""
    source = (target.source or "").strip()
    if target.profile == "ha":
        return source if _REPO.match(source) else None
    m = _GITHUB_URL.match(source)
    return m[1] if m else None


def md_text(text: object) -> str:
    """Untrusted prose as Markdown that shows the same text: no formatting, links or
    HTML, and no @mentions or #references, which GitHub would turn into notifications
    and links to other people's issues."""
    out = []
    for line in str(text or "").replace("\r", "").split("\n"):
        line = _MARKUP.sub(r"\\\1", line.strip())
        if re.match(r"\d+[.)]", line):  # a numbered list
            line = re.sub(r"^(\d+)", r"\1\\", line, count=1)
        elif line[:1] in ("#", "+", "-", "="):  # a heading, a list, a rule
            line = "\\" + line
        line = re.sub(r"@(?=\w)", "@" + WORD_JOINER, line)
        out.append(re.sub(r"#(?=\d)", "#" + WORD_JOINER, line))
    return "\n".join(out).strip("\n")


def md_code(text: object) -> str:
    """Untrusted text as one inline code span."""
    s = " ".join(str(text or "").split())
    if not s:
        return ""
    tick = "`" * (max((len(r) for r in re.findall(r"`+", s)), default=0) + 1)
    pad = " " if s[0] == "`" or s[-1] == "`" else ""
    return f"{tick}{pad}{s}{pad}{tick}"


def md_block(text: object, language: str = "") -> str:
    """Untrusted text as a fenced code block it can't close."""
    s = str(text or "").replace("\r", "").strip("\n")
    fence = "`" * max(3, max((len(r) for r in re.findall(r"`+", s)), default=0) + 1)
    return f"{fence}{language}\n{s}\n{fence}"


def _language(file: str | None) -> str:
    if not file:
        return ""
    path = PurePosixPath(file)
    return "dockerfile" if path.name == "Dockerfile" else LANGUAGES.get(path.suffix.lower(), "")


def _advisory(vuln_id: object) -> str:
    v = str(vuln_id)
    if _GHSA.match(v):
        return f"[{v}](https://github.com/advisories/{v})"
    if _CVE.match(v):
        return f"[{v}](https://www.cve.org/CVERecord?id={v})"
    return md_code(v)


def source_link(repo: str | None, scan: Scan | None, f: Finding) -> str | None:
    """The finding's line on GitHub, at the commit (or tag) that was scanned."""
    rev = scan and (scan.commit_sha or scan.ref)
    if not (repo and rev and f.file) or f.file.startswith("/") or ".." in f.file.split("/"):
        return None
    url = f"https://github.com/{repo}/blob/{quote(rev)}/{quote(f.file)}"
    return url + (f"#L{f.line}" if f.line and f.line > 0 else "")


def issue_title(f: Finding) -> str:
    title = " ".join((f.title or f.rule_id).split())
    return (f"{title} in {f.file}" if f.file else title)[:200]


def finding_markdown(f: Finding, scan: Scan | None, explanation: AiNote | None = None) -> str:
    """One finding as Markdown: what was found, where, in which version, the code excerpt
    and, if given, the AI's explanation, marked as such. For an add-on the explanation's
    advice is left out: it is written for someone deciding whether to install it, not
    for its author."""
    target = f.target
    link = source_link(github_repo(target), scan, f)
    where = f"{f.file}:{f.line}" if f.file and f.line else f.file or ""
    facts = [f"**Severity:** {md_text(f.severity)}",
             f"**Found by:** {md_text(f.scanner)}, rule {md_code(f.rule_id)}"]  # fmt: skip
    if where:
        facts.append("**Where:** " + (f"[{md_code(where)}]({link})" if link else md_code(where)))
    if scan and (scan.ref or scan.commit_sha):
        sha = f"commit {md_code(scan.commit_sha[:12])}" if scan.commit_sha else ""
        version = f"{md_code(scan.ref)} ({sha})" if scan.ref and sha else md_code(scan.ref) or sha
        facts.append(f"**Version scanned:** {version}")
    if f.vulns and f.vulns.get("groups"):
        ids = "; ".join(" = ".join(_advisory(v) for v in g) for g in f.vulns["groups"])
        package = f.vulns.get("package")
        facts.append("**Vulnerabilities:** " + (f"{md_code(package)}: " if package else "") + ids)

    parts = [f"### {md_text(f.title)}", "\n".join(f"- {fact}" for fact in facts)]
    if f.message and f.message.strip() != (f.title or "").strip():
        parts.append(md_text(f.message))
    if f.evidence and f.scanner not in SECRET_SCANNERS:
        parts.append(md_block(f.evidence, _language(f.file)))
    answer = explanation.result if explanation and explanation.status == "done" else None
    if answer:
        parts.append(f"#### Explanation by {md_code(explanation.model or 'an AI model')}")
        parts.append("*Written by an AI model from what the scanner recorded. It can be wrong.*")
        if answer.get("summary"):
            parts.append(md_text(answer["summary"]))
        if answer.get("real") in REAL:
            parts.append(f"**{REAL[answer['real']]}:** {md_text(answer.get('reason'))}")
        if answer.get("fix") and target.profile == "owned":
            parts.append(f"**What to do:** {md_text(answer['fix'])}")
    return "\n\n".join(parts) + "\n"


def new_issue_url(repo: str, title: str, body: str) -> tuple[str, bool]:
    """GitHub's new-issue page for `repo`, filled in; and whether the body fit (a long
    one would make the address too long, so then only the title is filled in)."""
    base = f"https://github.com/{repo}/issues/new?"
    url = base + urlencode({"title": title, "body": body})
    if len(url) <= ISSUE_URL_MAX:
        return url, True
    return base + urlencode({"title": title}), False
