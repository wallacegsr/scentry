"""What Barkley does for Home Assistant targets after and between scans.

What an update changes: when a scan is done, Barkley compares its report with an earlier
one (`sniff-test diff`, offline: two report files, nothing fetched) and the comparison is
kept on the scan. An offered update is compared with the installed version, an advisory
re-check with the scan it re-checked, anything else with the last scan of another version.

Advisories asked again: a vulnerability published after a version was scanned never
showed until the next rescan, a week later. Once a day (SCENTRY_RECHECK_HOURS) the
runner, when it has nothing queued, asks OSV again about the packages each installed and
offered version resolved (kept in Barkley's store). No code is fetched and GitHub isn't
asked anything. When the advisories changed, the result is a new scan of kind "recheck"
with Barkley's rescored report, compared with the scan it re-checked; the notifier sees
it like any finished scan.

Plain words for stored reports: the portal shows what Barkley's panel says about each rule
and app (barkley.plain). Scans stored before it did get them when the runner is idle.
"""

from __future__ import annotations

import datetime
import logging
import shutil
import tempfile
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from scentry import findings
from scentry.config import Settings
from scentry.models import Scan, Target, utcnow
from scentry.scanners import ScannerRun, barkley

log = logging.getLogger(__name__)
RETRY = datetime.timedelta(hours=1)  # after a re-check that couldn't ask OSV
ACTIVE = ("queued", "running")


class _Work:
    """A scratch folder for one comparison or re-check."""

    def __init__(self, settings: Settings):
        self.path = Path(tempfile.mkdtemp(prefix="barkley-", dir=settings.work_dir))

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, *_exc) -> None:
        shutil.rmtree(self.path, ignore_errors=True)


def _done(session: Session, target_id: int):
    return select(Scan).where(Scan.target_id == target_id, Scan.status == "done",
                              Scan.score.is_not(None))  # fmt: skip


def _same_ref(ref: str | None):
    return Scan.ref.is_(None) if ref is None else Scan.ref == ref


def _with_report(session: Session, query) -> Scan | None:
    for scan in session.scalars(query.order_by(Scan.id.desc()).limit(20)):
        if scan.report:
            return scan
    return None


# --- what an update changes ----------------------------------------------------------


def base_for(session: Session, scan: Scan) -> Scan | None:
    """The scan to compare this one with."""
    if scan.kind == "recheck" and scan.recheck_of:
        return session.get(Scan, scan.recheck_of)
    target = scan.target
    q = _done(session, target.id).where(Scan.id != scan.id)
    if target.update_offered and scan.ref == target.available_version:
        return _with_report(session, q.where(Scan.ref == target.installed_version))
    if scan.ref is None:
        return None  # no versions to tell apart
    q = q.where(Scan.id < scan.id, Scan.ref.is_not(None), Scan.ref != scan.ref)
    if target.update_offered:
        q = q.where(Scan.ref != target.available_version)  # newer, not before
    return _with_report(session, q)


def compare(session: Session, scan: Scan, base: Scan | None, settings: Settings) -> bool:
    """Keep Barkley's comparison of `base` and `scan` on the scan. A comparison that
    fails is logged and changes nothing: it never fails the scan."""
    if base is None or not base.report or not scan.report:
        return False
    try:
        with _Work(settings) as work:
            diff = barkley.compare(base.report, scan.report, work, settings.scanner_timeout)
    except Exception:
        log.exception("scan %s: no comparison with scan %s", scan.id, base.id)
        return False
    scan.diff, scan.diff_from = diff, base.id
    return True


def after_scan(session: Session, scan: Scan, settings: Settings) -> None:
    """A Home Assistant scan is done: compare it; and when it is of the installed version
    and an update is offered, compare the offered version with it again."""
    try:
        compare(session, scan, base_for(session, scan), settings)
        target = scan.target
        if target.update_offered and scan.ref == target.installed_version:
            offered = _with_report(session, _done(session, target.id).where(
                Scan.ref == target.available_version))  # fmt: skip
            if offered is not None and offered.diff_from != scan.id:
                compare(session, offered, scan, settings)
    except Exception:
        log.exception("scan %s: comparison failed", scan.id)


# --- advisories asked again ----------------------------------------------------------


def schedule(scan: Scan, settings: Settings, now: datetime.datetime) -> None:
    """When a scan Barkley stored has its advisories asked again."""
    if scan.barkley_id is not None and settings.recheck_hours > 0:
        scan.advisories_next_at = now + datetime.timedelta(hours=settings.recheck_hours)


def candidates(session: Session) -> list[Scan]:
    """The newest scan of each version that matters: installed and offered for a target
    found in Home Assistant, the last one scanned for one added by hand. Those Barkley
    didn't store (or that were rescanned since without its store) aren't re-checked."""
    busy = set(session.scalars(select(Scan.target_id).where(Scan.status.in_(ACTIVE))))
    out = []
    targets = session.scalars(select(Target).where(
        Target.enabled, Target.profile == "ha", Target.hacs_removed_at.is_(None)))  # fmt: skip
    for target in targets:
        if target.id in busy:
            continue  # a fresh scan is on its way
        if target.origin == "hacs":
            refs = {target.installed_version, target.available_version} - {None}
        else:
            latest = session.scalar(_done(session, target.id).order_by(Scan.id.desc()).limit(1))
            refs = {latest.ref} if latest is not None else set()
        for ref in refs:
            newest = session.scalar(
                _done(session, target.id).where(_same_ref(ref)).order_by(Scan.id.desc()).limit(1)
            )
            if newest is not None and newest.barkley_id is not None:
                out.append(newest)
    return out


def due(session: Session, settings: Settings, now: datetime.datetime) -> Scan | None:
    """The scan whose advisories are most overdue for another look, if any is due."""
    if not settings.barkley_store or settings.recheck_hours <= 0:
        return None
    every = datetime.timedelta(hours=settings.recheck_hours)

    def when(s: Scan) -> datetime.datetime:
        return s.advisories_next_at or (s.advisories_checked_at or s.finished_at or now) + every

    ready = [s for s in candidates(session) if when(s) <= now]
    return min(ready, key=when, default=None)


def recheck(session: Session, base: Scan, settings: Settings,
            now: datetime.datetime | None = None) -> Scan | None:  # fmt: skip
    """Ask OSV again about one scan's packages. The new scan when the advisories changed."""
    now = now or utcnow()
    every = datetime.timedelta(hours=settings.recheck_hours)
    with _Work(settings) as work:
        res = barkley.recheck(settings.barkley_store, base.barkley_id, work,
                              settings.scanner_timeout)  # fmt: skip
        words = barkley.plain(res.report, work, settings.scanner_timeout) if res.report else None
    if res.state == "error":
        log.warning("scan %s: advisories couldn't be asked again: %s", base.id, res.detail)
        base.advisories_error, base.advisories_next_at = res.detail, now + RETRY
        session.commit()
        return None
    base.advisories_checked_at, base.advisories_error = now, None
    base.advisories_next_at = now + every
    if res.state == "same":
        log.info("scan %s: advisories unchanged", base.id)
        session.commit()
        return None

    report = res.report or {}
    found = barkley.findings_of(report)
    run = ScannerRun("barkley", "ok", "advisories asked again", findings=found)
    new = Scan(
        target_id=base.target_id, kind="recheck", recheck_of=base.id, status="done",
        ref=base.ref, commit_sha=base.commit_sha, queued_at=now, started_at=now,
        finished_at=now, complete=base.complete and bool(report.get("complete")),
        score=report.get("score"), verdict=(report.get("verdict") or {}).get("label"),
        report=report, barkley_id=res.barkley_id, scanner_runs=[run.summary()],
        advisories_checked_at=now,
        advisories_next_at=now + every if res.barkley_id is not None else None,
    )  # fmt: skip
    if words is not None:  # else asked again later (plain_due): None here would be JSON null
        new.plain = words
    session.add(new)
    session.flush()
    # The target's findings stand for its newest scan: a re-check of an older one (the
    # installed version, with the offered one scanned since) leaves them alone.
    newest = session.scalar(_done(session, base.target_id).where(Scan.id != new.id)
                            .order_by(Scan.id.desc()).limit(1))  # fmt: skip
    if newest is not None and newest.id == base.id:
        findings.reconcile(session, new.target, new, [run], now)
    compare(session, new, base, settings)
    session.commit()
    log.info("scan %s: advisories changed, now scan %s (%s -> %s)", base.id, new.id,
             base.score, new.score)  # fmt: skip
    return new


def recheck_due(session: Session, settings: Settings, now: datetime.datetime | None = None) -> bool:
    """One re-check, if one is due. True when one ran."""
    now = now or utcnow()
    base = due(session, settings, now)
    if base is None:
        return False
    log.info("scan %s: asking OSV again about %s %s", base.id, base.target.name, base.ref or "")
    base_id = base.id
    try:
        recheck(session, base, settings, now)
    except Exception as exc:
        log.exception("scan %s: advisory re-check failed", base_id)
        session.rollback()
        base = session.get(Scan, base_id)
        base.advisories_error = f"{type(exc).__name__}: {exc}"[:300]
        base.advisories_next_at = now + RETRY  # not again on the next loop
        session.commit()
    return True


# --- Barkley's plain words for reports stored before it was asked ---------------------


def plain_due(session: Session, settings: Settings) -> bool:
    """Ask Barkley for its plain words about one stored report that has none yet (scans
    from before the portal showed them), newest first. Read from the stored report alone:
    nothing is fetched. True when one was asked."""
    if barkley.barkley_python() is None:
        return False
    scan = session.scalar(
        select(Scan).where(Scan.status == "done", Scan.report.is_not(None),
                           Scan.plain.is_(None)).order_by(Scan.id.desc()).limit(1)
    )  # fmt: skip
    if scan is None:
        return False
    words = None
    if scan.report:
        with _Work(settings) as work:
            words = barkley.plain(scan.report, work, settings.scanner_timeout)
    # Asked once: a failure isn't asked again until a new scan.
    scan.plain = words or {"error": "Barkley couldn't be asked"}
    if "error" in scan.plain:
        log.warning("scan %s: no plain words from Barkley: %s", scan.id, scan.plain["error"])
    session.commit()
    return True
