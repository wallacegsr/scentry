"""Fingerprints, the finding lifecycle across scans, and grading."""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from scentry.models import SEVERITY_RANK, Finding, Scan, Target, utcnow
from scentry.scanners.base import RawFinding, ScannerRun

SUPPRESSION_REASONS = ("false_positive", "accepted_risk", "wont_fix")
DEFAULT_SUPPRESSION_DAYS = 90


def fingerprint(f: RawFinding) -> str:
    """Stable across rescans: the scanner's own id when it has one, otherwise the rule,
    the file and the matched text. The line number is used only as a last resort, so
    code that merely moves keeps its finding (and its suppression)."""
    where = f.fingerprint_hint or " ".join((f.evidence or "").split()) or str(f.line or "")
    digest = hashlib.sha256()
    for part in (f.scanner, f.rule_id, f.file or "", where):
        digest.update(part.encode("utf-8", "replace"))
        digest.update(b"\0")
    return digest.hexdigest()


def reconcile(
    session: Session,
    target: Target,
    scan: Scan,
    runs: list[ScannerRun],
    now: datetime.datetime | None = None,
) -> None:
    """Fold one scan's results into the target's findings.

    - new fingerprint -> open; seen again after being fixed -> reopened
    - a suppression past its expiry -> open again, for another look
    - open and not reported any more -> fixed, but only if the scanner that found it
      ran successfully this time (a broken scanner fixes nothing)
    """
    now = now or utcnow()
    existing = {
        f.fingerprint: f
        for f in session.scalars(select(Finding).where(Finding.target_id == target.id))
    }
    for f in existing.values():
        if f.status == "suppressed" and f.suppressed_until and f.suppressed_until <= now:
            f.status = "open"
            f.suppressed_until = None
            f.opened_scan_id = scan.id  # back for another look

    ran_ok = {r.name for r in runs if r.state == "ok"}
    seen: set[str] = set()
    repeats: dict[str, int] = {}
    reported: set[tuple] = set()
    for run in runs:
        if run.state != "ok":
            continue
        for raw in run.findings:
            fp = fingerprint(raw)
            # A tool that lists the very same result twice (osv-scanner does) reported it once.
            same = (fp, raw.line, raw.message)
            if same in reported:
                continue
            reported.add(same)
            # The same rule matching identical text twice in one file is two findings:
            # the second and later ones are told apart by their order.
            nth = repeats[fp] = repeats.get(fp, -1) + 1
            if nth:
                fp = hashlib.sha256(f"{fp}:{nth}".encode()).hexdigest()
            seen.add(fp)
            f = existing.get(fp)
            if f is None:
                f = Finding(target_id=target.id, fingerprint=fp, scanner=raw.scanner,
                            rule_id=raw.rule_id, first_seen_at=now,
                            opened_scan_id=scan.id)  # fmt: skip
                session.add(f)
                existing[fp] = f
            elif f.status == "fixed":
                f.status = "open"
                f.fixed_at = None
                f.opened_scan_id = scan.id
            f.title, f.message, f.severity = raw.title, raw.message, raw.severity
            f.category, f.file, f.line, f.evidence = raw.category, raw.file, raw.line, raw.evidence
            f.vulns = raw.vulns
            f.last_seen_at, f.last_seen_scan_id = now, scan.id

    for fp, f in existing.items():
        if fp not in seen and f.status == "open" and f.scanner in ran_ok:
            f.status = "fixed"
            f.fixed_at = now
    session.flush()  # ids for the new findings
    mark_duplicates(list(existing.values()))


# --- one vulnerability, many ids ---------------------------------------------------

# Which report of a vulnerability is kept when two scanners report it: osv-scanner's
# (one finding per vulnerability) before Barkley's (one per package, several in one).
_PREFER = {"osv-scanner": 0, "barkley": 1}


def _package(name: object) -> str | None:
    """Package names compared the way registries do (PEP 503 for Python)."""
    if not name:
        return None
    return "-".join(part for part in str(name).lower().replace("_", "-").replace(".", "-")
                    .split("-") if part)  # fmt: skip


def mark_duplicates(target_findings) -> None:
    """Set `same_as` on each finding that only reports vulnerabilities another finding
    already reports: under another id (osv-scanner names a CVE, Barkley the GHSA), or in
    one finding per package where the other has one per vulnerability. Ids are linked
    through every alias any scanner listed. A fixed finding neither covers nor is
    covered; a suppressed one still covers (suppressing a vulnerability under one id
    suppresses it), so its twin isn't counted either."""
    parent: dict[str, str] = {}

    def root(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    live, groups = [], {}
    for f in target_findings:
        f_groups = [g for g in ((f.vulns or {}).get("groups") or []) if g]
        if f.status == "fixed" or not f_groups:
            if f.same_as is not None:
                f.same_as = None
            continue
        live.append(f)
        groups[id(f)] = f_groups
        for g in f_groups:
            for other in g[1:]:
                parent[root(other)] = root(g[0])

    covered: dict[str, list[tuple[str | None, object]]] = {}
    order = sorted(live, key=lambda f: (len(groups[id(f)]), _PREFER.get(f.scanner, 9), f.id or 0))
    for f in order:
        pkg = _package((f.vulns or {}).get("package"))
        keys = {root(g[0]) for g in groups[id(f)]}
        holder = None
        for key in sorted(keys):
            match = next((h for p, h in covered.get(key, [])
                          if p is None or pkg is None or p == pkg), None)  # fmt: skip
            if match is None:
                holder = None
                break
            holder = holder or match
        same_as = holder.id if holder is not None else None
        if f.same_as != same_as:
            f.same_as = same_as
        if holder is None:
            for key in keys:
                covered.setdefault(key, []).append((pkg, f))


# --- grading (profile "owned") -----------------------------------------------------

DEDUCTIONS = {"critical": 25, "high": 10, "medium": 3, "low": 1, "info": 0}
CAP_CRITICAL = 69  # an open critical finding: D at best
CAP_HIGH = 89  # an open high finding: no A
CAP_INCOMPLETE = 89  # a scan with a missing or failed scanner: no A
GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))


@dataclass
class Issue:
    """One problem for grading: every open finding of one rule, which may be reported in
    many places, and by another scanner too."""

    scanner: str
    rule_id: str
    title: str
    severity: str  # the worst of its findings
    count: int
    places: frozenset = frozenset()  # (file, line) of each finding that has a file
    also: list[str] = field(default_factory=list)  # other scanners' rules, same places

    @property
    def deduction(self) -> int:
        return DEDUCTIONS.get(self.severity, 0)


def issues(open_findings) -> list[Issue]:
    """Open findings folded into issues, worst first.

    - one rule is one issue, however many places it is found in: thirteen unpinned
      actions are one thing to fix, not thirteen;
    - two scanners' rules that flag exactly the same places are one issue (Semgrep and
      zizmor both report unpinned actions, for instance), at the worse severity.
    Rules that only share some places are different problems and stay apart.
    - a finding that reports only vulnerabilities another finding reports (`same_as`)
      is that finding's issue, not one of its own.
    """
    by_rule: dict[tuple[str, str], Issue] = {}
    by_id = {f.id: f for f in open_findings if getattr(f, "id", None) is not None}
    twins = []
    for f in open_findings:
        if getattr(f, "same_as", None) is not None:
            twins.append(f)  # counted with what it repeats (not at all if that's suppressed)
            continue
        key = (f.scanner, f.rule_id)
        issue = by_rule.get(key)
        if issue is None:
            issue = by_rule[key] = Issue(f.scanner, f.rule_id, f.title, f.severity, 0)
        issue.count += 1
        if SEVERITY_RANK.get(f.severity, 9) < SEVERITY_RANK.get(issue.severity, 9):
            issue.severity, issue.title = f.severity, f.title
        if f.file:
            issue.places = issue.places | {(f.file, f.line)}
    for f in twins:
        holder = by_id.get(f.same_as)
        issue = by_rule.get((holder.scanner, holder.rule_id)) if holder is not None else None
        if issue is None:
            continue
        also = f"{f.scanner}: {f.rule_id}"
        if also not in issue.also:
            issue.also.append(also)
        if SEVERITY_RANK.get(f.severity, 9) < SEVERITY_RANK.get(issue.severity, 9):
            issue.severity = f.severity  # the worse of the two reports
    ordered = sorted(by_rule.values(), key=lambda i: (SEVERITY_RANK.get(i.severity, 9),
                                                       -i.count, i.scanner, i.rule_id))  # fmt: skip
    kept: list[Issue] = []
    for issue in ordered:  # the worse of a duplicate pair comes first and absorbs the other
        twin = next((k for k in kept if k.scanner != issue.scanner and k.places
                     and k.places == issue.places), None)  # fmt: skip
        if twin is None:
            kept.append(issue)
        else:
            twin.also.append(f"{issue.scanner}: {issue.rule_id}")
    return kept


def grade(open_findings, complete: bool) -> tuple[int, str]:
    """Deterministic: the same open findings always give the same score. Each issue
    (see `issues`) costs its severity's deduction once; the caps still apply."""
    found = issues(open_findings)
    severities = {i.severity for i in found}
    score = max(0, 100 - sum(i.deduction for i in found))
    if "critical" in severities:
        score = min(score, CAP_CRITICAL)
    if "high" in severities:
        score = min(score, CAP_HIGH)
    if not complete:
        score = min(score, CAP_INCOMPLETE)
    return score, next(letter for floor, letter in GRADES if score >= floor)
