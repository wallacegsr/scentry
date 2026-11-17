"""One scan, start to finish: acquire -> sanitize -> scan -> reconcile -> score."""

from __future__ import annotations

import logging
import os
import shutil
import stat
import tempfile
from pathlib import Path

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from scentry import acquire, findings
from scentry.config import Settings
from scentry.models import Finding, Scan, Target, utcnow
from scentry.scanners import ScanContext, Scanner, ScannerRun, execute, scanners_for

log = logging.getLogger(__name__)


def _force_remove(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)  # git marks pack files read-only
    func(path)


def run_scan(
    session: Session, scan: Scan, settings: Settings, scanners: list[Scanner] | None = None
) -> None:
    target = scan.target
    work = Path(tempfile.mkdtemp(prefix="scan-", dir=settings.work_dir))
    try:
        out_dir = work / "out"
        out_dir.mkdir()
        ctx = ScanContext(settings, target.profile, target.source, scan.ref or target.ref, out_dir)
        if target.profile == "owned":
            ctx.tree = work / "tree"
            scan.commit_sha = acquire.acquire(target.source, ctx.ref, ctx.tree, settings)
            acquire.sanitize(ctx.tree, settings)

        runs: list[ScannerRun] = []
        for scanner in scanners if scanners is not None else scanners_for(target.profile):
            log.info("scan %s: %s", scan.id, scanner.name)
            runs.append(execute(scanner, ctx))

        retry_at = max((r.extra["retry_at"] for r in runs if r.extra.get("retry_at")),
                       default=None)  # fmt: skip
        if retry_at is not None:
            raise _Deferred(retry_at)

        findings.reconcile(session, target, scan, runs)
        session.flush()
        scan.scanner_runs = [r.summary() for r in runs]
        scan.complete = all(r.state in ("ok", "not_applicable") for r in runs)
        _score(session, scan, runs)
        scan.status = "done"
    except _Deferred as wait:
        session.rollback()
        defer_github_scans(session, wait.until)
        scan.status, scan.started_at, scan.not_before = "queued", None, wait.until
        log.info("scan %s: GitHub's API limit is used up; scans wait until %s UTC",
                 scan.id, f"{wait.until:%H:%M}")  # fmt: skip
    except acquire.AcquireError as exc:
        session.rollback()
        scan.status, scan.error = "failed", str(exc)
    except Exception as exc:
        log.exception("scan %s failed", scan.id)
        session.rollback()
        scan.status, scan.error = "failed", f"{type(exc).__name__}: {exc}"[:1000]
    finally:
        shutil.rmtree(work, onerror=_force_remove)
        if scan.status != "queued":
            scan.finished_at = utcnow()
        session.commit()


class _Deferred(Exception):
    def __init__(self, until):
        super().__init__(until)
        self.until = until


def defer_github_scans(session: Session, until) -> None:
    """Hold every queued Home Assistant scan (those fetch through GitHub's API) until
    the limit resets: running them now would only fail."""
    ha_targets = select(Target.id).where(Target.profile == "ha")
    session.execute(
        update(Scan)
        .where(Scan.status == "queued", Scan.target_id.in_(ha_targets),
               or_(Scan.not_before.is_(None), Scan.not_before < until))
        .values(not_before=until)
    )  # fmt: skip


def _score(session: Session, scan: Scan, runs: list[ScannerRun]) -> None:
    if scan.target.profile == "ha":
        # Barkley's score and verdict stand as they are; nothing here adjusts them.
        barkley = next((r for r in runs if r.name == "barkley" and r.state == "ok"), None)
        if barkley is None:
            scan.complete = False
            return
        extra = barkley.extra
        scan.score, scan.verdict = extra.get("score"), extra.get("verdict")
        scan.complete = scan.complete and bool(extra.get("complete"))
        scan.commit_sha = extra.get("commit_sha") or scan.commit_sha
        scan.ref = scan.ref or extra.get("ref")
        scan.report = extra.get("report")
        return
    open_findings = session.scalars(
        select(Finding).where(Finding.target_id == scan.target_id, Finding.status == "open")
    ).all()
    scan.score, scan.verdict = findings.grade(open_findings, scan.complete)
