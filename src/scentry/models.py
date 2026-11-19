"""Database model: targets, the scans run on them, and the findings that persist across scans."""

from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, String, Text, UniqueConstraint, false, true
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

    # My code: scan each new commit on the branch (ref, or the default branch). The
    # runner asks the git host for the branch's head now and then (commits.py).
    watch_commits: Mapped[bool] = mapped_column(default=True, server_default=true())
    head_sha: Mapped[str | None] = mapped_column(String(64), default=None)  # last seen
    head_checked_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    head_error: Mapped[str | None] = mapped_column(Text, default=None)

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
    ai_notes: Mapped[list[AiNote]] = relationship(cascade="all, delete-orphan")


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

    # "scan", or "recheck": made by asking OSV again about an earlier scan's packages
    # (recheck_of) after its advisories changed. Its code wasn't fetched again.
    kind: Mapped[str] = mapped_column(String(10), default="scan", server_default="scan")
    recheck_of: Mapped[int | None] = mapped_column(default=None)
    # The same scan in Barkley's own store on the runner, which keeps the packages it
    # resolved: what an advisory re-check asks about. None: can't be re-checked.
    barkley_id: Mapped[int | None] = mapped_column(default=None)
    advisories_checked_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    advisories_next_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    advisories_error: Mapped[str | None] = mapped_column(Text, default=None)
    # What changed since diff_from (another scan of this target): Barkley's comparison.
    diff_from: Mapped[int | None] = mapped_column(default=None)
    diff: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    # Barkley's plain words for `report` (scanners/barkley_plain.py): each rule explained,
    # what the app can do inside Home Assistant, its privacy notes. None: not asked yet;
    # {"error": ...}: Barkley couldn't say.
    plain: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)

    target: Mapped[Target] = relationship(back_populates="scans")

    @property
    def headline(self) -> list[dict[str, Any]]:
        """The changes in the comparison that matter, most important first."""
        d = self.diff or {}
        cut = d.get("headline_rank", 40)
        top = [c for c in d.get("changes") or [] if isinstance(c, dict) and
               isinstance(c.get("rank"), int) and c["rank"] >= cut]  # fmt: skip
        return top[:12]


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
    # A known vulnerability's ids, grouped per vulnerability, and its package (RawFinding).
    vulns: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    # Reports only vulnerabilities that finding already reports (another scanner, or
    # another id for the same one): shown, but counted and announced once, there.
    same_as: Mapped[int | None] = mapped_column(default=None)
    # What the scanner says about its rule, beyond this result: {"about": text, "url":
    # its documentation (https)}. Untrusted text, like the rest.
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)

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
    catalog_size: Mapped[int] = mapped_column(default=0, server_default="0")
    catalog_at: Mapped[datetime.datetime | None] = mapped_column(default=None)


class CatalogItem(Base):
    """One integration or card in the Home Assistant Marketplace, as the hass-sync service
    last read it: what the portal searches. Every text field is the publisher's own."""

    __tablename__ = "catalog"

    id: Mapped[int] = mapped_column(primary_key=True)
    repo: Mapped[str] = mapped_column(String(201), unique=True)  # owner/name, validated
    kind: Mapped[str] = mapped_column(String(20))  # integration | card
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    version: Mapped[str | None] = mapped_column(String(100), default=None)  # would install
    stars: Mapped[int] = mapped_column(default=0)
    downloads: Mapped[int | None] = mapped_column(default=None)
    installed: Mapped[bool] = mapped_column(default=False)
    seen_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)


class AiNote(Base):
    """Claude's explanation of one finding, or review of one scan: asked for in the portal,
    written by the ai service. `result` is model output about untrusted text: shown, never
    acted on."""

    __tablename__ = "ai_notes"
    __table_args__ = (UniqueConstraint("kind", "subject_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    kind: Mapped[str] = mapped_column(String(10))  # "finding" | "scan"
    subject_id: Mapped[int] = mapped_column()  # the finding's or the scan's id
    status: Mapped[str] = mapped_column(String(10), default="queued", index=True)
    requested_by: Mapped[str | None] = mapped_column(String(200), default=None)
    requested_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime.datetime | None] = mapped_column(default=None)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    model: Mapped[str | None] = mapped_column(String(100), default=None)  # that answered
    input_tokens: Mapped[int | None] = mapped_column(default=None)
    output_tokens: Mapped[int | None] = mapped_column(default=None)


class AiState(Base):
    """Status of the ai service (one row), for the portal: whether to offer explanations.
    Never holds the API key."""

    __tablename__ = "ai_state"

    id: Mapped[int] = mapped_column(primary_key=True)
    configured: Mapped[bool] = mapped_column(default=False)  # a model is set up
    provider: Mapped[str | None] = mapped_column(String(20), default=None)  # anthropic...
    model: Mapped[str | None] = mapped_column(String(100), default=None)
    daily_limit: Mapped[int] = mapped_column(default=0)  # 0: none
    day: Mapped[str | None] = mapped_column(String(10), default=None)  # UTC date of `used`
    used: Mapped[int] = mapped_column(default=0)  # requests sent that day
    seen_at: Mapped[datetime.datetime | None] = mapped_column(default=None)  # heartbeat
    error: Mapped[str | None] = mapped_column(Text, default=None)  # the last failed request
    error_at: Mapped[datetime.datetime | None] = mapped_column(default=None)


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


class LogEntry(Base):
    """One message from a service's log, for the portal's Log page (logs.py)."""

    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime.datetime] = mapped_column(index=True)
    service: Mapped[str] = mapped_column(String(20))  # web, runner, hass-sync, notify, ai
    level: Mapped[int]  # Python logging's: 20 info, 30 warning, 40 error, 50 critical
    logger: Mapped[str] = mapped_column(String(100))  # e.g. scentry.pipeline
    message: Mapped[str] = mapped_column(Text)  # with a traceback, if there was one
