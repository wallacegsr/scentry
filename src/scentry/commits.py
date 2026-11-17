"""Scanning my code on new commits.

The interval schedule rescans every target now and then (new advisories, new rules). On
top of that, for a repository of mine the runner, when it has nothing queued, asks the
git host every SCENTRY_COMMIT_POLL_MINUTES what the branch points at (`git ls-remote`,
with the same per-host token as a clone, nothing downloaded) and queues a scan when that
commit hasn't been scanned. Polling, not webhooks: the portal needn't be reachable from
the internet.
"""

from __future__ import annotations

import datetime
import logging

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from scentry import acquire, worker
from scentry.config import Settings
from scentry.models import Scan, Target, utcnow

log = logging.getLogger(__name__)


def due(session: Session, settings: Settings, now: datetime.datetime) -> Target | None:
    """The watched target whose branch was asked about longest ago, if one is due."""
    if settings.commit_poll_minutes <= 0:
        return None
    cutoff = now - datetime.timedelta(minutes=settings.commit_poll_minutes)
    busy = select(Scan.target_id).where(Scan.status.in_(worker.ACTIVE))
    return session.scalar(
        select(Target)
        .where(Target.profile == "owned", Target.enabled, Target.watch_commits,
               Target.source.startswith("https://"), Target.id.not_in(busy),
               or_(Target.head_checked_at.is_(None), Target.head_checked_at <= cutoff))
        .order_by(Target.head_checked_at.is_not(None), Target.head_checked_at, Target.id)
        .limit(1)
    )  # fmt: skip


def check(session: Session, target: Target, settings: Settings,
          now: datetime.datetime | None = None) -> Scan | None:  # fmt: skip
    """Ask for the branch's head; queue a scan if that commit hasn't been scanned."""
    now = now or utcnow()
    target.head_checked_at = now
    try:
        head = acquire.remote_head(target.source, target.ref, settings)
    except acquire.AcquireError as exc:
        if target.head_error != str(exc):
            log.warning("%s: %s", target.name, exc)
        target.head_error = str(exc)[:1000]
        session.commit()
        return None
    target.head_error = None
    seen, target.head_sha = target.head_sha, head
    if head == seen:
        session.commit()
        return None
    scanned = session.scalar(
        select(Scan.id).where(Scan.target_id == target.id, Scan.commit_sha == head,
                              Scan.status.in_(("done", *worker.ACTIVE))).limit(1)
    )  # fmt: skip
    if scanned is not None:
        session.commit()
        return None
    log.info("%s: new commit %s, queued", target.name, head[:12])
    return worker.enqueue(session, target, target.ref)  # commits


def check_due(session: Session, settings: Settings, now: datetime.datetime | None = None) -> bool:
    """One check, if one is due. True when one ran."""
    now = now or utcnow()
    target = due(session, settings, now)
    if target is None:
        return False
    check(session, target, settings, now)
    return True
