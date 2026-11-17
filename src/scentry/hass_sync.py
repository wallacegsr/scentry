"""The hass-sync service: keeps Scentry's targets in step with what the Home Assistant
Marketplace (HACS) has installed, and queues scans.

- an integration or card that is installed becomes an "HA integration" target, and the
  version that is installed gets scanned (so does each new version after an update);
- an update the Marketplace offers is scanned before you install it;
- an uninstalled one stops being rescanned, and keeps its history;
- the whole catalog (names, descriptions, versions) is kept for the portal's search.

The list is read at start, after every install or uninstall HA reports (HA 2026.11+),
every SCENTRY_HASS_POLL_SECONDS as a fallback, and when someone presses "Sync now".
This service only reads names and versions; it never touches installed code, and the
scans themselves run in the runner like any other.
"""

from __future__ import annotations

import datetime
import logging
import time
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scentry import db, worker
from scentry.config import Settings, get_settings
from scentry.hass import (
    Connection,
    HassError,
    Installed,
    Listed,
    matters,
    parse_catalog,
    parse_installed,
)
from scentry.models import CatalogItem, HassSync, Scan, Target, utcnow

log = logging.getLogger(__name__)

SETTLE_SECONDS = 3  # after HA says an install ended, before the list is read
REQUEST_CHECK_SECONDS = 5  # how often the portal's "Sync now" is looked for
FAILED_RETRY = datetime.timedelta(hours=1)
FAILED_ATTEMPTS = 3  # a version whose scan failed this often waits for the schedule


@dataclass
class SyncResult:
    queued: list[tuple[str, str, str]] = field(default_factory=list)  # repo, version, why
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)


def status_row(session: Session) -> HassSync:
    row = session.get(HassSync, 1)
    if row is None:
        row = HassSync(id=1)
        session.add(row)
        session.flush()
    return row


def needs_scan(session: Session, target: Target, version: str, now: datetime.datetime) -> bool:
    """True when this version has no scan yet, or only failed ones that are worth another
    try. A scan already waiting or running counts as done."""
    scans = session.scalars(
        select(Scan).where(Scan.target_id == target.id, Scan.ref == version).order_by(Scan.id)
    ).all()
    if not scans:
        return True
    if any(s.status in worker.ACTIVE for s in scans):
        return False
    if any(s.status == "done" and s.score is not None for s in scans):
        return False
    last = scans[-1]
    waited = (last.finished_at or last.queued_at) + FAILED_RETRY <= now
    return len(scans) < FAILED_ATTEMPTS and waited


def apply(
    session: Session,
    items: list[Installed],
    settings: Settings,
    now: datetime.datetime | None = None,
) -> SyncResult:
    """Fold one read of the installed list into the targets and the queue."""
    now = now or utcnow()
    result = SyncResult()
    ha_targets = session.scalars(select(Target).where(Target.profile == "ha")).all()
    by_repo = {t.source.lower(): t for t in ha_targets}

    seen: set[int] = set()
    for item in items:
        target = by_repo.get(item.repo.lower())
        if target is None:
            target = Target(
                name=item.name,
                profile="ha",
                source=item.repo,
                interval_hours=settings.hass_scan_interval_hours,
            )
            session.add(target)
            by_repo[item.repo.lower()] = target
            result.added.append(item.repo)
        target.origin = "hacs"
        target.hacs_kind = item.kind
        target.installed_version = item.installed
        target.available_version = item.available or None
        # Scheduled rescans scan what is installed, not the newest release.
        target.ref = item.installed
        target.hacs_seen_at, target.hacs_removed_at = now, None
        target.enabled = True
        session.flush()
        seen.add(target.id)

        if needs_scan(session, target, item.installed, now):
            worker.enqueue(session, target, item.installed, commit=False)
            result.queued.append((item.repo, item.installed, "installed"))
        if item.update and needs_scan(session, target, item.available, now):
            worker.enqueue(session, target, item.available, commit=False)
            result.queued.append((item.repo, item.available, "update offered"))

    for target in ha_targets:
        if target.origin == "hacs" and target.id not in seen and target.hacs_removed_at is None:
            target.hacs_removed_at = now
            target.installed_version = target.available_version = None
            target.enabled = False  # don't keep rescanning what you no longer run
            result.removed.append(target.source)
    session.commit()
    return result


def store_catalog(session: Session, listed: list[Listed], now: datetime.datetime) -> None:
    """Keep the portal's copy of the catalog in step: changed rows updated, new ones
    added, ones the Marketplace dropped deleted."""
    existing = {c.repo.lower(): c for c in session.scalars(select(CatalogItem))}
    for item in listed:
        row = existing.pop(item.repo.lower(), None)
        if row is None:
            row = CatalogItem(repo=item.repo)
            session.add(row)
        fields = {"repo": item.repo, "kind": item.kind, "name": item.name,
                  "description": item.description, "version": item.version or None,
                  "stars": item.stars, "downloads": item.downloads,
                  "installed": item.installed}  # fmt: skip
        for key, value in fields.items():
            if getattr(row, key) != value:
                setattr(row, key, value)
        row.seen_at = now
    for row in existing.values():
        session.delete(row)
    status = status_row(session)
    status.catalog_size, status.catalog_at = len(listed), now


def sync_once(session: Session, conn: Connection, settings: Settings) -> SyncResult:
    row = status_row(session)
    row.last_attempt_at = utcnow()
    session.commit()
    raw, source = conn.list_repositories()
    items, skipped = parse_installed(raw)
    result = apply(session, items, settings)
    try:
        store_catalog(session, parse_catalog(raw), utcnow())
    except Exception:  # the search is a convenience: never let it stop the sync
        log.exception("couldn't store the Marketplace catalog")
        session.rollback()
    row = status_row(session)
    row.last_ok_at, row.error = utcnow(), None
    row.installed, row.skipped, row.source = len(items), skipped, source
    row.ha_version = conn.ha_version or row.ha_version
    session.commit()
    for repo, version, why in result.queued:
        log.info("queued %s %s (%s)", repo, version, why)
    for repo in result.removed:
        log.info("%s is no longer installed", repo)
    log.info("synced: %s installed, %s skipped %s", len(items), sum(skipped.values()), skipped)
    return result


def _record_error(message: str) -> None:
    with db.SessionLocal() as session:
        row = status_row(session)
        row.last_attempt_at, row.error, row.listening = utcnow(), message[:1000], False
        session.commit()


def _requested(session: Session, since: datetime.datetime) -> bool:
    requested = session.scalar(select(HassSync.requested_at).where(HassSync.id == 1))
    return requested is not None and requested > since


def run_connected(conn: Connection, settings: Settings) -> None:
    """Sync, then wait for events, the poll interval or a "Sync now"; until the
    connection fails (HassError)."""
    with db.SessionLocal() as session:
        sync_once(session, conn, settings)
        listening = conn.subscribe()
        status_row(session).listening = listening
        session.commit()
    log.info("listening for installs" if listening else "this HA can't report installs: polling")

    last_sync = utcnow()
    next_poll = time.monotonic() + settings.hass_poll_seconds
    while True:
        event = conn.next_event(timeout=REQUEST_CHECK_SECONDS)
        reason = None
        if event is not None and matters(*event):
            time.sleep(SETTLE_SECONDS)
            reason = "install event"
        elif time.monotonic() >= next_poll:
            reason = "poll"
        else:
            with db.SessionLocal() as session:
                if _requested(session, last_sync):
                    reason = "requested"
        if reason:
            log.info("syncing (%s)", reason)
            last_sync = utcnow()
            with db.SessionLocal() as session:
                sync_once(session, conn, settings)
            next_poll = time.monotonic() + settings.hass_poll_seconds


def main(settings: Settings | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = settings or get_settings()
    db.configure(settings.database_url)
    if not settings.hass_url:
        log.info("SCENTRY_HASS_URL is not set: Home Assistant sync is off")
        while True:  # stay up quietly, so a stack with this service unused is healthy
            time.sleep(3600)
    if settings.hass_url.startswith("http://"):
        log.warning("Connecting to Home Assistant over plain http: the token crosses your "
                    "network unencrypted.")  # fmt: skip

    backoff = 10
    while True:
        conn = None
        try:
            conn = Connection(settings.hass_url, settings.hass_token,
                              verify_tls=settings.hass_verify_tls,
                              ca_file=settings.hass_ca_file)  # fmt: skip
            log.info("connected to Home Assistant %s", conn.ha_version)
            backoff = 10
            run_connected(conn, settings)
        except HassError as exc:
            log.warning("Home Assistant sync: %s", exc)
            _record_error(str(exc))
        except Exception as exc:
            log.exception("Home Assistant sync failed")
            _record_error(f"{type(exc).__name__}: {exc}")
        finally:
            if conn is not None:
                conn.close()
        time.sleep(backoff)
        backoff = min(backoff * 2, max(60, settings.hass_poll_seconds))


def installed_counts(session: Session) -> dict[str, int]:
    """Installed targets by kind, for the status line."""
    rows = session.execute(
        select(Target.hacs_kind, func.count())
        .where(Target.origin == "hacs", Target.hacs_removed_at.is_(None))
        .group_by(Target.hacs_kind)
    ).all()
    return {kind or "unknown": n for kind, n in rows}
