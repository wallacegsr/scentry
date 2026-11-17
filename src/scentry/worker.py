"""The runner: takes queued scans one at a time and queues the scheduled ones. With
nothing queued, it asks advisories again for versions scanned a day ago (updates.py).

The queue is the scans table, so a restart loses nothing. Run a single runner: a scan
found "running" at start-up is assumed to be this runner's own interrupted work.
"""

from __future__ import annotations

import datetime
import logging
import time

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from scentry import db, pipeline, updates
from scentry.config import Settings, get_settings
from scentry.models import Scan, Target, utcnow

log = logging.getLogger(__name__)
ACTIVE = ("queued", "running")


def enqueue(
    session: Session, target: Target, ref: str | None = None, *, commit: bool = True
) -> Scan:
    """Queue a scan of `ref`, or return the one already waiting or running for that ref.
    A target can have scans of two versions waiting (installed, and an update offered)."""
    same_ref = Scan.ref.is_(None) if ref is None else Scan.ref == ref
    active = session.scalar(
        select(Scan)
        .where(Scan.target_id == target.id, Scan.status.in_(ACTIVE), same_ref)
        .limit(1)
    )
    if active:
        return active
    scan = Scan(target_id=target.id, ref=ref)
    session.add(scan)
    if commit:
        session.commit()
    else:
        session.flush()
    return scan


def claim(session: Session, now: datetime.datetime | None = None) -> Scan | None:
    ready = or_(Scan.not_before.is_(None), Scan.not_before <= (now or utcnow()))
    scan_id = session.scalar(
        select(Scan.id).where(Scan.status == "queued", ready).order_by(Scan.id).limit(1)
    )
    if scan_id is None:
        return None
    won = session.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status == "queued")
        .values(status="running", started_at=utcnow())
    )
    session.commit()
    return session.get(Scan, scan_id) if won.rowcount == 1 else None


def requeue_interrupted(session: Session) -> int:
    res = session.execute(
        update(Scan).where(Scan.status == "running").values(status="queued", started_at=None)
    )
    session.commit()
    return res.rowcount


def schedule_due(session: Session, now: datetime.datetime | None = None) -> int:
    """Queue every enabled target whose last scan is older than its interval."""
    now = now or utcnow()
    queued = 0
    targets = session.scalars(select(Target).where(Target.enabled, Target.interval_hours > 0))
    for target in targets.all():
        last = session.scalar(  # an advisory re-check fetched no code: not a scan of it
            select(Scan).where(Scan.target_id == target.id, Scan.kind != "recheck")
            .order_by(Scan.id.desc()).limit(1)
        )  # fmt: skip
        if last is not None:
            if last.status in ACTIVE:
                continue
            since = last.finished_at or last.queued_at
            if since + datetime.timedelta(hours=target.interval_hours) > now:
                continue
        enqueue(session, target, target.ref)
        queued += 1
    return queued


def main(settings: Settings | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = settings or get_settings()
    db.configure(settings.database_url)
    with db.SessionLocal() as session:
        if n := requeue_interrupted(session):
            log.info("re-queued %s interrupted scan(s)", n)
        # A restart may come with a GitHub token: try held scans now. If the limit still
        # holds, the first scan to meet it holds them again.
        session.execute(update(Scan).where(Scan.status == "queued").values(not_before=None))
        session.commit()
    log.info("runner ready")
    last_schedule = 0.0
    while True:
        with db.SessionLocal() as session:
            if time.monotonic() - last_schedule > 60:
                schedule_due(session)
                last_schedule = time.monotonic()
            scan = claim(session)
            if scan is not None:
                log.info("scan %s: %s (%s)", scan.id, scan.target.name, scan.target.profile)
                pipeline.run_scan(session, scan, settings)
                log.info("scan %s: %s", scan.id, scan.status)
                continue
            # Nothing queued: one advisory re-check, if one is due (seconds of work).
            try:
                if updates.recheck_due(session, settings):
                    continue
            except Exception:
                log.exception("advisory re-checks failed")
                session.rollback()
        time.sleep(settings.poll_seconds)
