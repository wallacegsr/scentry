"""The notify service: tells you when a scan found something worth a look.

It reads finished scans from the database, decides which matter, and sends one digest
through Apprise to whatever you use: ntfy, Gotify, Discord, Telegram, e-mail, Pushover,
a Home Assistant webhook, and many more. It waits for the queue to drain, though for no
longer than SCENTRY_NOTIFY_MAX_WAIT_MINUTES, so the first sync of a Home Assistant with
thirty integrations is one message, not thirty.

What is announced:
- a Home Assistant integration or card that scores under SCENTRY_NOTIFY_SCORE_BELOW, the
  first time that version does (a weekly rescan with the same result stays quiet), or
  that scores 10 points worse than the last scan of the same version;
- an offered update that scores under the threshold, or 10 points worse than the version
  installed (every offered update with SCENTRY_NOTIFY_CLEAN_UPDATES);
- my code: findings at SCENTRY_NOTIFY_MIN_SEVERITY or above that a scan found or reopened;
- a new advisory: the daily re-check of an installed or offered version's packages made
  it newly bad, 10 points worse, or found a high or critical vulnerability;
- a target whose scans start failing, and a Home Assistant sync failing for 30 minutes.

An offered update's message lists what it changes (Barkley's comparison with the
installed version) when there is a comparison, its worst findings otherwise.

Each target can be muted, or override any of those settings, on its page in the portal.

Text that comes from scanned code (names, paths, rule titles) is cut down to a plain
character set before it goes into a message, so it can't carry mentions, markup or links.
This service holds the notification URLs (they contain secrets) and nothing else does.
"""

from __future__ import annotations

import datetime
import logging
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from scentry import db, worker
from scentry.config import Settings, get_settings
from scentry.models import (
    SEVERITIES,
    SEVERITY_RANK,
    Finding,
    HassSync,
    NotifyState,
    Scan,
    Target,
    utcnow,
)

log = logging.getLogger(__name__)

LOOP_SECONDS = 15
STALE = datetime.timedelta(hours=24)  # older results are recorded, never announced
HASS_GRACE = datetime.timedelta(minutes=30)
HEARTBEAT = datetime.timedelta(minutes=5)  # the portal calls the notifier gone after this
REGRESSION = 10  # points
MAX_ITEMS = 10
MAX_LINES = 5
LEVELS = ("failure", "warning", "info")  # worst first

_UNSAFE = re.compile(r"[^A-Za-z0-9 ._,;()'/+#-]+")


def safe(text: object, limit: int = 120) -> str:
    """Untrusted text reduced to letters, digits and dull punctuation: no @mentions, no
    markdown or HTML, no "scheme://" links, no control characters."""
    text = " ".join(_UNSAFE.sub(" ", str(text or "")).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


@dataclass
class Item:
    level: str  # failure | warning | info
    head: str  # a few words, the title of a message with only this in it
    text: str
    lines: list[str] = field(default_factory=list)
    scan_id: int | None = None
    at: datetime.datetime | None = None  # when it happened, for the digest's deadline


@dataclass(frozen=True)
class Rules:
    """What gets a message, for one target: the SCENTRY_NOTIFY_* defaults with that
    target's own settings on top."""

    score_below: int  # ha: a verdict under this
    min_severity: str  # owned: findings this bad or worse
    clean_updates: bool  # ha: every offered update, the fine ones too
    failures: bool  # scans starting to fail

    @classmethod
    def defaults(cls, settings: Settings) -> Rules:
        return cls(settings.notify_score_below, settings.notify_min_severity,
                   settings.notify_clean_updates, settings.notify_failures)  # fmt: skip

    def for_target(self, target: Target) -> Rules | None:
        """None when the target is muted."""
        if target.notify_muted:
            return None

        def pick(own, default):
            return default if own is None else own

        return Rules(
            pick(target.notify_score_below, self.score_below),
            pick(target.notify_min_severity, self.min_severity),
            pick(target.notify_clean_updates, self.clean_updates),
            pick(target.notify_failures, self.failures),
        )

    def as_dict(self) -> dict:
        return {"score_below": self.score_below, "min_severity": self.min_severity,
                "clean_updates": self.clean_updates, "failures": self.failures}  # fmt: skip


def state_row(session: Session) -> NotifyState:
    row = session.get(NotifyState, 1)
    if row is None:
        row = NotifyState(id=1)
        session.add(row)
        session.flush()
    return row


# --- deciding -----------------------------------------------------------------------------


def _label(target: Target) -> str:
    name = safe(target.name, 60)
    if target.profile != "ha":
        return name
    if name.lower() == target.source.rsplit("/", 1)[-1].lower():
        return target.source  # a validated owner/repo
    return f"{name} ({target.source})"


def _result(scan: Scan) -> str:
    if scan.target.profile == "ha":
        return f"{scan.score}, {safe(scan.verdict, 40)}"
    return f"grade {safe(scan.verdict, 2)} ({scan.score})"


def _scored(session: Session, target_id: int, *, ref: str | None = None,
            before: int | None = None) -> Scan | None:  # fmt: skip
    q = select(Scan).where(Scan.target_id == target_id, Scan.status == "done",
                           Scan.score.is_not(None))  # fmt: skip
    if ref is not None:
        q = q.where(Scan.ref == ref)
    if before is not None:
        q = q.where(Scan.id < before)
    return session.scalar(q.order_by(Scan.id.desc()).limit(1))


def _finding_line(severity, title, scanner, file, line) -> str:
    where = f" in {safe(file, 80)}{f':{line}' if isinstance(line, int) else ''}" if file else ""
    return f"{safe(severity, 10)}: {safe(title, 90)} ({safe(scanner, 20)}){where}"


def _barkley_lines(scan: Scan) -> list[str]:
    """The worst findings of this version, from Barkley's own report."""
    found = [f for f in (scan.report or {}).get("findings") or [] if isinstance(f, dict)]
    found = [f for f in found if SEVERITY_RANK.get(str(f.get("severity")).lower(), 9) <= 1]
    found.sort(key=lambda f: SEVERITY_RANK.get(str(f.get("severity")).lower(), 9))
    lines = [_finding_line(str(f.get("severity")).lower(), f.get("title") or f.get("rule_id"),
                           "barkley", f.get("file"), f.get("line"))
             for f in found[:MAX_LINES]]  # fmt: skip
    if len(found) > MAX_LINES:
        lines.append(f"and {len(found) - MAX_LINES} more")
    return lines


_SIGNS = {"+": "new", "-": "gone", "~": "changed"}
SERIOUS = ("critical", "high")


def _diff_lines(scan: Scan) -> list[str]:
    """What this version changes that matters, from Barkley's comparison."""
    top = scan.headline
    lines = []
    for c in top[:MAX_LINES]:
        sev = f" {safe(c.get('severity'), 10)}" if c.get("severity") else ""
        lines.append(f"{_SIGNS.get(c.get('sign'), 'changed')}{sev}: {safe(c.get('text'), 150)}")
    if len(top) > MAX_LINES:
        lines.append(f"and {len(top) - MAX_LINES} more")
    return lines


def _new_serious(scan: Scan) -> bool:
    """Barkley's comparison has a finding added at high or critical."""
    return any(isinstance(c, dict) and c.get("sign") == "+" and c.get("group") == "findings"
               and c.get("severity") in SERIOUS
               for c in (scan.diff or {}).get("changes") or [])  # fmt: skip


def _rechecked(session: Session, scan: Scan, rules: Rules) -> Item | None:
    """Advisories asked again changed a version's result: said when it got worse."""
    base = session.get(Scan, scan.recheck_of) if scan.recheck_of else None
    if base is None or base.score is None:
        return None
    bad = scan.score < rules.score_below
    worse = ((bad and base.score >= rules.score_below) or scan.score <= base.score - REGRESSION
             or _new_serious(scan))  # fmt: skip
    if not worse:
        return None
    target = scan.target
    what = f"{_label(target)} {safe(scan.ref, 40)}" if scan.ref else _label(target)
    if target.origin == "hacs" and target.hacs_removed_at is None:
        if scan.ref == target.installed_version:
            what += " (installed)"
        elif target.update_offered and scan.ref == target.available_version:
            what += " (update offered)"
    return Item("failure" if bad else "warning", "New advisory",
                f"New advisory: {what} now scores {_result(scan)} (was {_result(base)})",
                _diff_lines(scan) or _barkley_lines(scan), scan.id, scan.finished_at)  # fmt: skip


def _failed(session: Session, scan: Scan, rules: Rules) -> Item | None:
    if not rules.failures:
        return None
    previous = session.scalar(
        select(Scan)
        .where(Scan.target_id == scan.target_id, Scan.id < scan.id,
               Scan.status.in_(("done", "failed")))
        .order_by(Scan.id.desc()).limit(1)
    )  # fmt: skip
    if previous is not None and (previous.status == "failed" or previous.score is None):
        return None  # already failing: said once
    why = scan.error or "; ".join(
        f"{r.get('name')}: {r.get('detail')}" for r in scan.scanner_runs or []
        if r.get("state") not in ("ok", "not_applicable")
    ) or "no result"  # fmt: skip
    version = f" {safe(scan.ref, 40)}" if scan.ref else ""
    return Item("warning", "Scan failed", f"Scan failed: {_label(scan.target)}{version}",
                [safe(why, 200)], scan.id, scan.finished_at)  # fmt: skip


def _ha(session: Session, scan: Scan, rules: Rules) -> Item | None:
    target, score = scan.target, scan.score
    threshold = rules.score_below
    bad = score < threshold
    installed = target.origin == "hacs" and target.hacs_removed_at is None
    what = f"{_label(target)} {safe(scan.ref, 40)}" if scan.ref else _label(target)

    if installed and target.update_offered and scan.ref == target.available_version:
        current = _scored(session, target.id, ref=target.installed_version)
        worse = current is not None and score <= current.score - REGRESSION
        if not (bad or worse or rules.clean_updates):
            return None
        vs = (f"; installed {safe(target.installed_version, 40)} scored {_result(current)}"
              if current else "")  # fmt: skip
        # What the update changes, when Barkley compared it with the installed version.
        changes = _diff_lines(scan) if current and scan.diff_from == current.id else []
        if bad or worse:
            return Item("failure" if bad else "warning", "Update offered: look before installing",
                        f"Update offered: {what} scored {_result(scan)}{vs}",
                        changes or _barkley_lines(scan), scan.id, scan.finished_at)  # fmt: skip
        return Item("info", "Update offered: looks fine",
                    f"Update offered: {what} scored {_result(scan)}{vs}",
                    changes, scan.id, scan.finished_at)  # fmt: skip

    previous = _scored(session, target.id, ref=scan.ref, before=scan.id)
    newly_bad = bad and (previous is None or previous.score >= threshold)
    dropped = previous is not None and score <= previous.score - REGRESSION
    if not (newly_bad or dropped):
        return None
    if installed and scan.ref == target.installed_version:
        head = "Installed in Home Assistant"
    else:
        head = "Checked"
    was = f" (was {_result(previous)})" if previous else ""
    return Item("failure" if bad else "warning", head,
                f"{head}: {what} scores {_result(scan)}{was}",
                _barkley_lines(scan), scan.id, scan.finished_at)  # fmt: skip


def _owned(session: Session, scan: Scan, rules: Rules) -> Item | None:
    floor = SEVERITY_RANK[rules.min_severity]
    new = [
        f for f in session.scalars(select(Finding).where(
            Finding.target_id == scan.target_id, Finding.opened_scan_id == scan.id,
            Finding.status == "open"))
        if SEVERITY_RANK.get(f.severity, 9) <= floor
        and f.same_as is None  # a vulnerability another finding already reports
    ]  # fmt: skip
    if not new:
        return None
    new.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.scanner, f.file or ""))
    counts = Counter(f.severity for f in new)
    summary = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])
    lines = [_finding_line(f.severity, f.title, f.scanner, f.file, f.line)
             for f in new[:MAX_LINES]]  # fmt: skip
    if len(new) > MAX_LINES:
        lines.append(f"and {len(new) - MAX_LINES} more")
    n = len(new)
    return Item("failure" if counts["critical"] else "warning", "New findings",
                f"{_label(scan.target)}: {n} new finding{'s' if n != 1 else ''} ({summary}); "
                f"now {_result(scan)}", lines, scan.id, scan.finished_at)  # fmt: skip


def evaluate(session: Session, scan: Scan, settings: Settings) -> Item | None:
    """What, if anything, to say about one finished scan, by its target's rules."""
    rules = Rules.defaults(settings).for_target(scan.target)
    if rules is None:
        return None  # muted
    if scan.status == "failed" or scan.score is None:
        return _failed(session, scan, rules)
    if scan.kind == "recheck":
        return _rechecked(session, scan, rules)
    if scan.target.profile == "ha":
        return _ha(session, scan, rules)
    return _owned(session, scan, rules)


def collect(session: Session, settings: Settings, now: datetime.datetime) -> list[Item]:
    """The finished scans worth a message. Those with nothing to say, or that finished too
    long ago, are marked so and not looked at again; a scan waits while another scan of
    its target is still to run (an offered update is compared with the installed one)."""
    busy = set(session.scalars(select(Scan.target_id).where(Scan.status.in_(worker.ACTIVE))))
    pending = session.scalars(
        select(Scan).where(Scan.status.in_(("done", "failed")), Scan.notice.is_(None))
        .order_by(Scan.id)
    ).all()  # fmt: skip
    items = []
    for scan in pending:
        if (scan.finished_at or scan.queued_at) < now - STALE:
            scan.notice = "stale"
            continue
        if scan.target_id in busy:
            continue
        try:
            item = evaluate(session, scan, settings)
        except Exception:
            log.exception("couldn't evaluate scan %s", scan.id)
            item = None
        if item is None:
            scan.notice = "quiet"
        else:
            items.append(item)
    return items


def hass_item(session: Session, state: NotifyState, now: datetime.datetime) -> Item | None:
    sync = session.get(HassSync, 1)
    if sync is None or not sync.error:
        state.hass_failing_since, state.hass_alerted = None, False
        return None
    since = state.hass_failing_since = state.hass_failing_since or now
    if state.hass_alerted or now - since < HASS_GRACE:
        return None
    minutes = int((now - since).total_seconds() // 60)
    return Item("warning", "Home Assistant sync failing",
                f"Home Assistant sync has been failing for {minutes} minutes",
                [safe(sync.error, 200)], None, since + HASS_GRACE)  # fmt: skip


def compose(items: list[Item], settings: Settings) -> tuple[str, str, str]:
    """One message for all of them: title, body and the Apprise notify type."""
    items = sorted(items, key=lambda i: LEVELS.index(i.level))
    title = "Scentry: " + (items[0].head if len(items) == 1 else f"{len(items)} notices")
    base = settings.public_url.rstrip("/")
    blocks = []
    for item in items[:MAX_ITEMS]:
        lines = [item.text, *(f"  {line}" for line in item.lines)]
        if base and item.scan_id:
            lines.append(f"  {base}/scans/{item.scan_id}")
        blocks.append("\n".join(lines))
    if len(items) > MAX_ITEMS:
        rest = len(items) - MAX_ITEMS
        blocks.append(f"…and {rest} more{f' at {base}' if base else ' in the portal'}.")
    return title, "\n\n".join(blocks), items[0].level


# --- sending --------------------------------------------------------------------------------


class Sender:
    """Apprise, with the URLs. Errors it reports are scrubbed of anything from the URLs
    except the host, since they end up in the database and on the portal."""

    def __init__(self, urls: str):
        import apprise  # imported here: only this service needs it
        from apprise.utils.parse import parse_urls

        self._apprise = apprise
        self.apobj = apprise.Apprise(asset=apprise.AppriseAsset(storage_mode="memory"))
        listed = parse_urls(urls) if urls.strip() else []
        self.invalid = sum(1 for url in listed if not self.apobj.add(url))
        self.services = len(self.apobj)
        self._secrets = sorted(_secret_parts(listed), key=len, reverse=True)

    def scrub(self, text: str) -> str:
        for part in self._secrets:
            text = text.replace(part, "***")
        return text

    def send(self, title: str, body: str, level: str) -> tuple[bool, str | None]:
        """(delivered to at least one service, what went wrong where)."""
        ap = self._apprise
        kind = {"failure": ap.NotifyType.FAILURE, "warning": ap.NotifyType.WARNING}.get(
            level, ap.NotifyType.INFO
        )
        try:
            res = self.apobj.notify(body=body, title=title, notify_type=kind,
                                    body_format=ap.NotifyFormat.TEXT,
                                    interpret_escapes=False)  # fmt: skip
        except Exception as exc:  # a plugin bug must not stop the service
            return False, self.scrub(f"{type(exc).__name__}: {exc}")[:1000]
        failed = []
        for r in res.results:
            if r.status != ap.AppriseResultStatus.SUCCESS:
                logs = [getattr(e, "message", str(e)) for e in r.logs()]
                failed.append(f"{r.name}: {logs[-1] if logs else 'not delivered'}")
        error = self.scrub("; ".join(failed))[:1000] or None
        return res.success_count > 0, error


# Query settings that name a server or a mode, not a secret: hiding them in errors only
# makes the errors useless ("connection error to ***").
_NOT_SECRET = {"smtp", "mode", "format", "overflow", "priority", "method", "port", "name"}


def _secret_parts(urls: list[str]) -> set[str]:
    """User names, passwords, path segments and query values of every URL, where services
    keep tokens, topics and webhook ids; and the host part of those (tgram://, pover://)
    whose "host" is itself a token."""
    parts: set[str] = set()
    for url in urls:
        try:
            u = urlsplit(url)
            query = [v for k, v in parse_qsl(u.query) if k.lower() not in _NOT_SECRET]
            host = u.hostname or ""
        except ValueError:
            continue
        pieces = [u.username, u.password, *u.path.split("/"), *query]
        if "." not in host and host != "localhost":  # not a DNS name or an address
            pieces.append(url.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1])
        parts.update(p for p in pieces if p and len(p) >= 4)
    return parts


# --- the loop -------------------------------------------------------------------------------


def _backoff(failures: int) -> datetime.timedelta:
    return datetime.timedelta(minutes=min(2 ** max(failures - 1, 0), 60))


def run_once(session: Session, sender: Sender, settings: Settings,
             now: datetime.datetime | None = None) -> bool:  # fmt: skip
    """One pass: a requested test, then the digest when it is due. True if a digest went."""
    now = now or utcnow()
    state = state_row(session)
    state.seen_at, state.services, state.invalid_urls = now, sender.services, sender.invalid

    if state.test_requested_at and (
        state.test_done_at is None or state.test_requested_at > state.test_done_at
    ):
        ok, error = sender.send("Scentry: test", "Notifications from Scentry reach here.",
                                "info")  # fmt: skip
        state.test_done_at, state.test_ok = now, ok
        state.error, state.error_at = (error, now) if error else (None, state.error_at)
        session.commit()

    items = collect(session, settings, now)
    hass = hass_item(session, state, now)
    if hass:
        items.append(hass)
    if not items:
        session.commit()
        return False

    queue_busy = session.scalar(select(Scan.id).where(Scan.status.in_(worker.ACTIVE)).limit(1))
    oldest = min(i.at or now for i in items)
    deadline = oldest + datetime.timedelta(minutes=settings.notify_max_wait_minutes)
    retry_ok = not state.failures or now >= (state.error_at or now) + _backoff(state.failures)
    if (queue_busy and now < deadline) or not retry_ok:
        session.commit()
        return False

    delivered, error = sender.send(*compose(items, settings))
    if delivered:
        ids = {i.scan_id for i in items if i.scan_id}
        for scan in session.scalars(select(Scan).where(Scan.id.in_(ids))):
            scan.notice = "sent"
        state.hass_alerted = state.hass_alerted or hass is not None
        state.last_sent_at, state.failures = now, 0
        state.error, state.error_at = (error, now) if error else (None, None)
        log.info("sent %s notice%s", len(items), "s" if len(items) != 1 else "")
    else:
        state.failures += 1
        state.error, state.error_at = error or "not delivered", now
        log.warning("notification not delivered (attempt %s): %s", state.failures, state.error)
    session.commit()
    return delivered


def main(settings: Settings | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = settings or get_settings()
    db.configure(settings.database_url)
    sender = Sender(settings.notify_urls)
    if sender.invalid:
        log.error("%s of the notification URLs couldn't be read and are ignored",
                  sender.invalid)  # fmt: skip
    with db.SessionLocal() as session:
        state = state_row(session)
        state.services, state.invalid_urls, state.seen_at = (
            sender.services, sender.invalid, utcnow())  # fmt: skip
        state.defaults = Rules.defaults(settings).as_dict()  # shown in the portal
        state.failures = 0  # new settings, perhaps: try straight away, not after a backoff
        session.commit()
    if not sender.services:
        log.info("SCENTRY_NOTIFY_URLS is not set: notifications are off")
        while True:  # stay up quietly, so a stack with this service unused is healthy
            time.sleep(3600)
    log.info("notifications on: %s service%s", sender.services,
             "s" if sender.services != 1 else "")  # fmt: skip
    while True:
        try:
            with db.SessionLocal() as session:
                run_once(session, sender, settings)
        except Exception:
            log.exception("notify pass failed")
        time.sleep(LOOP_SECONDS)
