"""Database model: targets, the scans run on them, and the findings that persist across scans."""

from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, String, Text, UniqueConstraint, false
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

PROFILES = ("owned", "ha")
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def utcnow() -> datetime.datetime:
    """Naive UTC, so values compare the same on SQLite and Postgres."""
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Target(Base):
    """Something to scan.

    profile "owned": `source` is a clone URL (or a local path); findings are triaged.
    profile "ha": `source` is owner/repo of a Home Assistant integration or card; each
    scan is a verdict on the version the Marketplace (HACS) would install.
    """

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    profile: Mapped[str] = mapped_column(String(20))
    source: Mapped[str] = mapped_column(String(500))
    ref: Mapped[str | None] = mapped_column(String(200), default=None)
    interval_hours: Mapped[int] = mapped_column(default=168)  # 0 = manual scans only
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)

    # "manual": added in the portal. "hacs": found installed in Home Assistant by the
    # hass-sync service, which keeps the fields below current.
    origin: Mapped[str] = mapped_column(String(20), default="manual")
    hacs_kind: Mapped[str | None] = mapped_column(String(20), default=None)  # integration|card
    installed_version: Mapped[str | None] = mapped_column(String(100), default=None)
    available_version: Mapped[str | None] = mapped_column(String(100), default=None)
    hacs_seen_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    hacs_removed_at: Mapped[datetime.datetime | None] = mapped_column(default=None)

    # Notifications about this target. Muted: none at all. The rest override the
    # notifier's SCENTRY_NOTIFY_* defaults; None = use the default.
    notify_muted: Mapped[bool] = mapped_column(default=False, server_default=false())
    notify_score_below: Mapped[int | None] = mapped_column(default=None)  # ha
    notify_min_severity: Mapped[str | None] = mapped_column(String(10), default=None)  # owned
    notify_clean_updates: Mapped[bool | None] = mapped_column(default=None)  # ha, installed
    notify_failures: Mapped[bool | None] = mapped_column(default=None)

    @property
    def update_offered(self) -> bool:
        return bool(
            self.installed_version
            and self.available_version
            and self.available_version != self.installed_version
        )

    scans: Mapped[list[Scan]] = relationship(
        back_populates="target", cascade="all, delete-orphan", order_by="Scan.id.desc()"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    ref: Mapped[str | None] = mapped_column(String(200), default=None)
    commit_sha: Mapped[str | None] = mapped_column(String(64), default=None)
    queued_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    # A queued scan isn't started before this: set while GitHub's API limit is used up.
    not_before: Mapped[datetime.datetime | None] = mapped_column(default=None)
    # False when a scanner was missing, failed or timed out: such a scan never gets
    # the top grade.
    complete: Mapped[bool] = mapped_column(default=False)
    score: Mapped[int | None] = mapped_column(default=None)
    verdict: Mapped[str | None] = mapped_column(String(100), default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    scanner_runs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    report: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    # Set by the notifier once it has looked at a finished scan: "sent", "quiet"
    # (nothing worth a message), or "stale" (finished too long ago to announce).
    notice: Mapped[str | None] = mapped_column(String(10), default=None, index=True)

    target: Mapped[Target] = relationship(back_populates="scans")


class Finding(Base):
    """One issue in one target, identified by a fingerprint that survives rescans."""

    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("target_id", "fingerprint"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    scanner: Mapped[str] = mapped_column(String(50))
    rule_id: Mapped[str] = mapped_column(String(300))
    title: Mapped[str] = mapped_column(String(300))
    message: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(10))
    category: Mapped[str] = mapped_column(String(50), default="")
    file: Mapped[str | None] = mapped_column(String(1000), default=None)
    line: Mapped[int | None] = mapped_column(default=None)
    evidence: Mapped[str | None] = mapped_column(Text, default=None)  # untrusted text

    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    first_seen_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    last_seen_scan_id: Mapped[int | None] = mapped_column(default=None)
    opened_scan_id: Mapped[int | None] = mapped_column(default=None)  # found or reopened by
    fixed_at: Mapped[datetime.datetime | None] = mapped_column(default=None)

    suppression_reason: Mapped[str | None] = mapped_column(String(50), default=None)
    suppression_note: Mapped[str | None] = mapped_column(Text, default=None)
    suppressed_by: Mapped[str | None] = mapped_column(String(200), default=None)
    suppressed_until: Mapped[datetime.datetime | None] = mapped_column(default=None)

    target: Mapped[Target] = relationship(back_populates="findings")


class HassSync(Base):
    """Status of the Home Assistant sync (one row), shown on the portal's front page.
    The portal also uses it to ask the sync for an immediate run."""

    __tablename__ = "hass_sync"

    id: Mapped[int] = mapped_column(primary_key=True)
    last_attempt_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    last_ok_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    ha_version: Mapped[str | None] = mapped_column(String(40), default=None)
    source: Mapped[str | None] = mapped_column(String(60), default=None)  # which command
    listening: Mapped[bool] = mapped_column(default=False)  # subscribed to install events
    installed: Mapped[int] = mapped_column(default=0)
    skipped: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    requested_at: Mapped[datetime.datetime | None] = mapped_column(default=None)


class NotifyState(Base):
    """Status of the notifier (one row), shown on the portal's front page. The portal
    also uses it to ask for a test message. Never holds the notification URLs."""

    __tablename__ = "notify_state"

    id: Mapped[int] = mapped_column(primary_key=True)
    services: Mapped[int] = mapped_column(default=0)  # usable URLs; 0 = notifications off
    invalid_urls: Mapped[int] = mapped_column(default=0)  # URLs Apprise couldn't read
    seen_at: Mapped[datetime.datetime | None] = mapped_column(default=None)  # heartbeat
    last_sent_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)  # the last failed send
    error_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    failures: Mapped[int] = mapped_column(default=0)  # sends failed in a row
    test_requested_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    test_done_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    test_ok: Mapped[bool | None] = mapped_column(default=None)
    # The Home Assistant sync has been failing since then; alerted once per outage.
    hass_failing_since: Mapped[datetime.datetime | None] = mapped_column(default=None)
    hass_alerted: Mapped[bool] = mapped_column(default=False)
    # The notifier's SCENTRY_NOTIFY_* defaults, for the portal to show next to each
    # target's overrides (the portal isn't given those settings). No secrets.
    defaults: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
