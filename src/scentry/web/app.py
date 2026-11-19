"""The portal. Server-rendered, no JavaScript: the content security policy allows no
scripts at all, because the pages show text taken from scanned code. Tables sort and
search through query parameters (tables.py); pop-ups are the browser's own popovers."""

from __future__ import annotations

import base64
import binascii
import collections
import datetime
import ipaddress
import json
import logging
import re
import secrets
import threading
import time
import unicodedata
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode, urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from scentry import (
    __version__,
    acquire,
    ai,
    ai_providers,
    db,
    export,
    findings,
    hass_sync,
    logs,
    notify,
    sarif,
    worker,
)
from scentry.config import Settings, get_settings
from scentry.findings import DEFAULT_SUPPRESSION_DAYS, SUPPRESSION_REASONS
from scentry.models import (
    PROFILES,
    SEVERITIES,
    SEVERITY_RANK,
    AiState,
    CatalogItem,
    Finding,
    HassSync,
    LogEntry,
    NotifyState,
    RuleSuppression,
    Scan,
    Target,
    utcnow,
)
from scentry.web import report as barkley_report
from scentry.web.tables import ONCE, view

HERE = Path(__file__).parent
CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)


LOOKS = ("cards", "table")


def chosen_look(request: Request, what: str) -> tuple[str, bool]:
    """Cards or a table for a list ("targets" or "findings"): what the link asked for, else
    what was last chosen (a cookie), else a table. True when the link asked."""
    asked = request.query_params.get("view")
    if asked in LOOKS:
        return asked, True
    saved = request.cookies.get(f"scentry_{what}_view")
    return (saved if saved in LOOKS else "table"), False


def remember_look(response: Response, request: Request, what: str, look: str) -> Response:
    response.set_cookie(f"scentry_{what}_view", look, max_age=365 * 86400, path="/",
                        samesite="lax", httponly=True,
                        secure=request.url.scheme == "https")  # fmt: skip
    return response


def look_links(request: Request, anchor: str) -> dict[str, str]:
    """The same page as cards or as a table, sorted and searched as it is."""
    keep = [(k, v) for k, v in request.query_params.multi_items()
            if k != "view" and k not in ONCE]  # fmt: skip
    return {look: f"?{urlencode([*keep, ('view', look)])}#{anchor}" for look in LOOKS}


def app_parts(scan: Scan | None, name: str) -> dict | None:
    """What Barkley's report of one scan says about the app beyond its findings, for
    _app.html: where its data can go, what it can do inside Home Assistant, the
    developer's security habits. None without a report."""
    rep = scan.report if scan is not None and isinstance(scan.report, dict) else None
    if not rep or not isinstance(rep.get("graph"), dict):
        return None
    plain = barkley_report.words(scan)
    return {"flow": barkley_report.flow(rep, plain, name),
            "connects": barkley_report.connection_sentence(rep, plain),
            "hosts": barkley_report.hosts(rep), "ports": barkley_report.ports(rep, plain),
            "privacy": plain.get("privacy") or [], "can_do": plain.get("can_do") or [],
            "habits": barkley_report.habits(rep),
            "popularity": barkley_report.popularity(rep)}  # fmt: skip


def _graded(scans: list[Scan], version: str | None) -> Scan | None:
    """The newest finished scan with a result: of `version` when one is given (what is
    installed), otherwise of anything."""
    for scan in scans:
        if scan.status == "done" and scan.verdict and (version is None or scan.ref == version):
            return scan
    return None


REFRESH_SECONDS = 10
CATALOG_PAGE = 50  # search results shown
LOG_PAGE = 100  # log messages on a page
PICK_MAX = 500  # findings suppressed at once
LOG_LEVELS = {"warning": logging.WARNING, "error": logging.ERROR}  # the Log page's filter
# Barkley's comparison buckets, in its order, as the scan page names them.
DIFF_GROUPS = {"findings": "findings", "flows": "data flows", "data": "data read",
               "hosts": "hosts", "packages": "packages", "hooks": "hooks",
               "repo": "publisher", "coverage": "coverage"}  # fmt: skip


def _duration(delta: datetime.timedelta) -> str:
    seconds = max(0, int(delta.total_seconds()))
    return f"{seconds // 60} min {seconds % 60} s" if seconds >= 60 else f"{seconds} s"


def progress(session: Session, scans: list[Scan], now: datetime.datetime) -> dict[int, str]:
    """For each waiting or running scan: how far along it is, in words."""
    out: dict[int, str] = {}
    running = None
    for scan in scans:
        if scan.status == "running":
            out[scan.id] = f"running for {_duration(now - (scan.started_at or now))}"
        elif scan.status == "queued" and scan.not_before and scan.not_before > now:
            out[scan.id] = f"waiting for GitHub's API limit until {scan.not_before:%H:%M} UTC"
        elif scan.status == "queued":
            if running is None:
                running = session.scalar(
                    select(func.count()).where(Scan.status == "running")) or 0  # fmt: skip
            ahead = running + (session.scalar(
                select(func.count()).where(
                    Scan.status == "queued", Scan.id < scan.id,
                    or_(Scan.not_before.is_(None), Scan.not_before <= now))
            ) or 0)  # fmt: skip
            plural = "s" if ahead != 1 else ""
            out[scan.id] = f"{ahead} scan{plural} ahead" if ahead else "starting"
    return out


def ago(when: datetime.datetime | None, now: datetime.datetime | None = None) -> str:
    if when is None:
        return "never"
    seconds = int(((now or utcnow()) - when).total_seconds())
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if seconds >= size:
            n = seconds // size
            return f"{n} {unit}{'s' if n != 1 else ''} ago"
    return "just now"


# The portal's lists of targets (each at /<key>), by name, and the profile a target added
# to one gets.
TABS = {"ha": "Home Assistant", "others": "Other integrations", "code": "My code",
        "repos": "Other repositories"}  # fmt: skip
TAB_PROFILE = {"others": "ha", "code": "owned", "repos": "owned"}


@dataclass(frozen=True)
class Group:
    """A tab of the tab bar, and the row of sub-tabs under it: its lists (and the
    Marketplace), each (key, short name). The tab opens the first."""

    label: str
    icon: str
    lists: tuple[tuple[str, str], ...]


GROUPS = {
    "hass": Group("Home Assistant", "ha", (("ha", "Installed"), ("others", "Not installed"),
                                            ("marketplace", "Marketplace"))),
    "repositories": Group("Repositories", "code", (("code", "Mine"), ("repos", "Others"))),
}  # fmt: skip
GROUP_OF = {key: name for name, g in GROUPS.items() for key, _ in g.lists}


def category(target: Target) -> str:
    """Which list a target is on: installed in Home Assistant; an integration or card that
    isn't installed (checked before installing, or removed); my code; or someone else's."""
    if target.origin == "hacs" and target.hacs_removed_at is None:
        return "ha"
    if target.profile != "owned":
        return "others"
    return "code" if target.mine else "repos"


def trail(tab: str | None) -> list[tuple[str, str]]:
    """The breadcrumbs to a list: its tab, then its sub-tab, as (url, name)."""
    group = GROUPS.get(GROUP_OF.get(tab or ""))
    if group is None:
        return []
    short = dict(group.lists)[tab]
    return [(f"/{group.lists[0][0]}", group.label), (f"/{tab}", short)]


_SCAN_REF = re.compile(r"\bscan (\d{1,10})\b")
LEVEL_NAMES = (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL)


def scan_links(text: str) -> list[tuple[str, int | None]]:
    """A log message in pieces, each "scan 12" in it with that scan's id. The template
    makes those pieces links, and escapes every piece like any other text."""
    pieces: list[tuple[str, int | None]] = []
    at = 0
    for m in _SCAN_REF.finditer(text):
        if m.start() > at:
            pieces.append((text[at:m.start()], None))
        pieces.append((m[0], int(m[1])))
        at = m.end()
    if at < len(text):
        pieces.append((text[at:], None))
    return pieces


def marks(text: str) -> list[tuple[str, str | None]]:
    """Evidence in pieces, each mark of a hidden character ("<U+202E>") with the
    character's name; the template shows those marked out, and escapes every piece."""
    pieces: list[tuple[str, str | None]] = []
    at = 0
    for m in sarif.MARK.finditer(text):
        if not sarif.hidden(m[1]):
            continue  # "<U+0041>" written in the code itself
        if m.start() > at:
            pieces.append((text[at:m.start()], None))
        name = unicodedata.name(chr(int(m[1], 16)), "").lower() or "a control character"
        pieces.append((m[0], name))
        at = m.end()
    if at < len(text):
        pieces.append((text[at:], None))
    return pieces


def level_name(level: int) -> str:
    return logging.getLevelName(level).lower() if level in LEVEL_NAMES else str(level)


def suppression_problem(reason: str, days: int) -> str | None:
    if reason not in SUPPRESSION_REASONS:
        return "A suppression needs a reason and a justification."
    if days < 0:
        return "Days can't be negative (0 is permanent)."
    return None


def suppression_until(days: int) -> datetime.datetime | None:
    """0 days: for good; otherwise back for review when the time is up."""
    return utcnow() + datetime.timedelta(days=min(days, 3650)) if days > 0 else None


def suppress_findings(chosen: list[tuple[Finding, str]], reason: str, days: int,
                      user: str) -> None:
    """Suppress each finding with its note, on its own."""
    until = suppression_until(days)
    for finding, note in chosen:
        finding.status, finding.suppressed_by, finding.suppressed_until = (
            "suppressed", user, until)  # fmt: skip
        finding.suppression_reason, finding.suppression_note = reason, note.strip()[:2000]
        finding.rule_suppression_id = None


def folder_of(path: str) -> str:
    """The pattern a rule suppression starts from: the file's folder, or the file itself
    when it's at the top of the repository."""
    return path.rsplit("/", 1)[0] + "/" if "/" in path else path


def bucket(score: int | None) -> str:
    """A score's colour: the letter grade it would be."""
    if score is None:
        return "none"
    return next(letter for floor, letter in findings.GRADES if score >= floor).lower()


def _trusted(host: str, cidrs: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(c, strict=False) for c in cidrs)


class SignInLimit:
    """Wrong passwords per client address. After LIMIT within WINDOW seconds that address
    is refused (even with the right password) until the oldest of them is WINDOW old:
    a few hundred guesses a day, where a password worth having needs billions."""

    LIMIT = 20
    WINDOW = 15 * 60
    MAX_ADDRESSES = 10_000

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failed: dict[str, deque[float]] = {}

    def _recent(self, who: str, now: float) -> deque[float]:
        seen = self._failed.get(who, deque())
        while seen and now - seen[0] >= self.WINDOW:
            seen.popleft()
        return seen

    def wait(self, who: str, now: float | None = None) -> int:
        """Seconds until `who` may try again; 0 if it may now."""
        now = time.monotonic() if now is None else now
        with self._lock:
            seen = self._recent(who, now)
            return int(self.WINDOW - (now - seen[0])) + 1 if len(seen) >= self.LIMIT else 0

    def failed(self, who: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            if who not in self._failed and len(self._failed) >= self.MAX_ADDRESSES:
                self._failed = {k: v for k, v in self._failed.items() if self._recent(k, now)}
                if len(self._failed) >= self.MAX_ADDRESSES:
                    self._failed = {}  # that many addresses at once: start over
            seen = self._recent(who, now)
            seen.append(now)
            self._failed[who] = seen


def make_auth(settings: Settings):
    limit = SignInLimit()

    def require_user(request: Request) -> str:
        if settings.auth_mode == "none":
            return "anonymous"
        if settings.auth_mode == "proxy":
            # The header means something only when it comes from the proxy itself.
            peer = request.client.host if request.client else ""
            if not _trusted(peer, settings.trusted_proxies):
                raise HTTPException(403, "Not from a trusted proxy.")
            user = request.headers.get(settings.proxy_user_header)
            if not user:
                raise HTTPException(401, "Not signed in.")
            return user
        scheme, _, value = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() == "basic":
            who = request.client.host if request.client else ""
            if wait := limit.wait(who):
                raise HTTPException(429, "Too many wrong passwords: try again later.",
                                    {"Retry-After": str(wait)})  # fmt: skip
            try:
                user, _, password = base64.b64decode(value).decode("utf-8").partition(":")
            except (binascii.Error, UnicodeDecodeError):
                user = password = ""
            user_ok = secrets.compare_digest(user.encode(), settings.admin_user.encode())
            pass_ok = secrets.compare_digest(password.encode(), settings.admin_password.encode())
            if user_ok and pass_ok:
                return user
            limit.failed(who)
        raise HTTPException(401, "Sign in.", {"WWW-Authenticate": 'Basic realm="Scentry"'})

    return require_user


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    if settings.auth_mode == "basic" and not settings.admin_password:
        raise RuntimeError("Set SCENTRY_ADMIN_PASSWORD (or choose another SCENTRY_AUTH_MODE).")
    if settings.auth_mode == "proxy" and not settings.trusted_proxies:
        raise RuntimeError("SCENTRY_AUTH_MODE=proxy needs SCENTRY_TRUSTED_PROXIES.")
    db.configure(settings.database_url)

    app = FastAPI(title="Scentry", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None)  # fmt: skip
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals.update(version=__version__, reasons=SUPPRESSION_REASONS,
                                 default_days=DEFAULT_SUPPRESSION_DAYS)  # fmt: skip
    templates.env.filters["ago"] = ago
    templates.env.filters["bucket"] = bucket
    templates.env.filters["scan_links"] = scan_links
    templates.env.filters["marks"] = marks
    templates.env.filters["level_name"] = level_name
    templates.env.filters["ai_label"] = ai_providers.label
    templates.env.globals["providers"] = ai_providers.PROVIDERS
    user_dep = Depends(make_auth(settings))
    session_dep = Depends(db.get_session)

    @app.middleware("http")
    async def harden(request: Request, call_next):
        # Cross-site form posts would ride on the browser's saved sign-in: refuse them.
        # Browsers say where a request comes from in Sec-Fetch-Site, which pages can't
        # set; Origin is the fallback for older ones. ("null" is what a browser sends
        # when it won't say: refused unless Sec-Fetch-Site vouches for the request.)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            site = request.headers.get("sec-fetch-site")
            origin = request.headers.get("origin")
            if site is not None:
                cross = site not in ("same-origin", "none")
            else:
                cross = origin is not None and (
                    urlsplit(origin).netloc != request.headers.get("host")
                )
            if cross:
                return PlainTextResponse("Cross-site request refused.", 403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        # same-origin, not no-referrer: with no-referrer browsers send "Origin: null" on
        # the portal's own forms. Links to other sites still carry no referrer.
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    def services(session: Session, now: datetime.datetime) -> dict:
        """The other services' state, as the System tab and the chips elsewhere show it:
        each is "ok", "bad" (needs looking at) or "off" (not set up)."""
        sync = session.get(HassSync, 1)
        notifier = session.get(NotifyState, 1)
        ai_state = session.get(AiState, 1)
        notifier_gone = bool(
            notifier and notifier.services
            and (notifier.seen_at is None or now - notifier.seen_at > notify.HEARTBEAT)
        )  # fmt: skip
        ai_gone = bool(ai_state and ai_state.configured and (
            ai_state.seen_at is None or now - ai_state.seen_at > ai.HEARTBEAT))  # fmt: skip
        ai_limit = ai.limit_reached(ai_state, now)
        if sync is None:
            hass = ("off", "not connected")
        elif sync.error:
            hass = ("bad", "not connected")
        else:
            hass = ("ok", f"synced {ago(sync.last_ok_at, now)}")
        if not notifier or not notifier.services:
            mail = ("off", "off")
        elif notifier_gone or notifier.error or notifier.invalid_urls:
            mail = ("bad", "not running" if notifier_gone else "a send failed"
                    if notifier.error else "a URL is unreadable")  # fmt: skip
        else:
            mail = ("ok", f"{notifier.services} service{'s' if notifier.services != 1 else ''}")
        if not ai_state or not ai_state.configured:
            model = ("off", "off")
        elif ai_gone or ai_state.error:
            model = ("bad", "not running" if ai_gone else "has a problem")
        else:
            model = ("ok", "today's limit used up" if ai_limit else ai_state.model)
        waiting = session.execute(
            select(func.count(), func.max(Scan.not_before))
            .where(Scan.status == "queued", Scan.not_before > now)
        ).one()  # fmt: skip
        chips = [("Home Assistant", *hass), ("Notifications", *mail), ("AI", *model)]
        if waiting[0]:
            chips.append(("GitHub", "bad", "API limit used up"))
        return {"sync": sync, "notifier": notifier, "notifier_gone": notifier_gone,
                "ai_state": ai_state, "ai_gone": ai_gone, "ai_limit": ai_limit,
                "ai_name": ai_name(ai_state),
                "waiting": waiting, "chips": chips}  # fmt: skip

    def ai_name(state: AiState | None) -> str:
        """Who answers explanations, as the pages name it: Claude, or the model's name."""
        if state is None or not state.configured:
            return "AI"
        return ai_providers.label(state.model, state.provider)

    def answering(session: Session) -> str:
        return f"{ai_name(session.get(AiState, 1))} is answering"

    def page(request: Request, session: Session, name: str, **context):
        """A page with the tab bar: each tab's count, and whether a service needs a look."""
        now = context.setdefault("now", utcnow())
        counts = dict.fromkeys(TABS, 0)
        for target in session.scalars(select(Target)):
            counts[category(target)] += 1
        state = context.get("state") or services(session, now)
        context.setdefault("ai_name", state["ai_name"])
        context.setdefault("tab", None)
        group_counts = {name: sum(counts.get(key, 0) for key, _ in g.lists)
                        for name, g in GROUPS.items()}  # fmt: skip
        context.update(tab_counts=counts, tabs=TABS, groups=GROUPS, group_counts=group_counts,
                       group=GROUP_OF.get(context["tab"] or ""), trail=trail(context["tab"]),
                       system_alert=any(c[1] == "bad" for c in state["chips"]))  # fmt: skip
        return templates.TemplateResponse(request, name, context)

    def get_target(session: Session, target_id: int) -> Target:
        target = session.get(Target, target_id)
        if target is None:
            raise HTTPException(404)
        return target

    def target_rows(session: Session, targets: list[Target]) -> list[dict]:
        """What a list shows about each target: its result, what is open, what's running."""
        open_by: dict[int, dict[str, int]] = {}
        for target_id, severity, n in session.execute(
            select(Finding.target_id, Finding.severity, func.count())
            .where(Finding.status == "open")
            .group_by(Finding.target_id, Finding.severity)
        ):  # fmt: skip
            open_by.setdefault(target_id, {})[severity] = n
        rows = []
        for target in targets:
            scans = target.scans  # newest first
            installed = category(target) == "ha"
            sev = open_by.get(target.id, {})
            finished = next((s for s in scans if s.status in ("done", "failed")), None)
            rows.append({
                "target": target,
                "tab": category(target),
                "busy": [s for s in scans if s.status in worker.ACTIVE],
                "graded": _graded(scans, target.installed_version if installed else None),
                "offered": (
                    next((s for s in scans if s.ref == target.available_version), None)
                    if installed and target.update_offered else None
                ),
                "open": sum(sev.values()),
                "sev": sev,
                "finished": finished,
                "failed": finished is not None and finished.status == "failed",
            })  # fmt: skip
        return rows

    def score_of(row: dict) -> int | None:
        return row["graded"].score if row["graded"] else None

    def last_of(row: dict) -> datetime.datetime | None:
        return row["finished"].finished_at if row["finished"] else None

    def row_text(row: dict) -> list[str | None]:
        t, g = row["target"], row["graded"]
        return [t.name, t.source, t.ref, t.hacs_kind, t.installed_version,
                t.available_version, g.verdict if g else None]  # fmt: skip

    def attention(row: dict) -> list[str]:
        """Why a target belongs on the overview's short list, if it does."""
        why = []
        g, offered, sev = row["graded"], row["offered"], row["sev"]
        if row["failed"]:
            why.append("its last scan failed")
        if g and g.score is not None and g.score < 70:
            why.append(f"scores {g.score}")
        if g and not g.complete:
            why.append("a scanner didn't finish")
        if offered and offered.status == "done" and offered.score is not None and (
                offered.score < 70 or (g and g.score is not None and offered.score < g.score)):
            why.append(f"update {row['target'].available_version} scores {offered.score}")
        bad = sev.get("critical", 0) + sev.get("high", 0)
        if bad:
            why.append(f"{bad} critical or high open")
        return why

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return PlainTextResponse("ok")

    @app.get("/")
    def overview(request: Request, session: Session = session_dep, user: str = user_dep):
        """At a glance: each tab's results, what needs a look, the latest scans."""
        now = utcnow()
        targets = session.scalars(select(Target).order_by(func.lower(Target.name))).all()
        rows = target_rows(session, list(targets))
        summary = {}
        for key in TABS:
            mine = [r for r in rows if r["tab"] == key]
            grades: dict[str, int] = {}
            for r in mine:
                b = bucket(score_of(r)) if r["graded"] else "none"
                grades[b] = grades.get(b, 0) + 1
            sev: dict[str, int] = {}
            for r in mine:
                for s, n in r["sev"].items():
                    sev[s] = sev.get(s, 0) + n
            summary[key] = {
                "count": len(mine), "grades": grades, "sev": sev,
                "busy": sum(1 for r in mine if r["busy"]),
                "updates": sum(1 for r in mine if r["target"].update_offered),
                "failed": sum(1 for r in mine if r["failed"]),
            }  # fmt: skip
        flagged = [{**r, "why": w} for r in rows if (w := attention(r))]
        flag = view(request.query_params, flagged, prefix="att_", anchor="attention",
                    sorts={"name": lambda r: r["target"].name, "tab": lambda r: TABS[r["tab"]],
                           "score": score_of, "last": last_of},
                    default="score", desc_first=("last",),
                    text=lambda r: [*row_text(r), *r["why"], TABS[r["tab"]]])  # fmt: skip
        recent_scans = session.scalars(
            select(Scan).where(Scan.status.in_(("done", "failed")))
            .order_by(Scan.finished_at.desc()).limit(12)
        ).all()  # fmt: skip
        recent = view(request.query_params, recent_scans, prefix="recent_", anchor="recent",
                      sorts={"target": lambda s: s.target.name, "score": lambda s: s.score,
                             "version": lambda s: s.ref, "finished": lambda s: s.finished_at},
                      default="finished", default_desc=True, desc_first=("score", "finished"),
                      text=lambda s: [s.target.name, s.ref, s.verdict, s.status,
                                      TABS[category(s.target)]])  # fmt: skip
        state = services(session, now)
        return page(request, session, "overview.html", tab="overview", summary=summary,
                    flag=flag, recent=recent, state=state, now=now, user=user,
                    category=category)  # fmt: skip

    @app.get("/ha")
    def tab_ha(request: Request, error: str = "", session: Session = session_dep,
               user: str = user_dep):  # fmt: skip
        return listing(request, session, "ha", error, user)

    @app.get("/code")
    def tab_code(request: Request, error: str = "", session: Session = session_dep,
                 user: str = user_dep):  # fmt: skip
        return listing(request, session, "code", error, user)

    @app.get("/others")
    def tab_others(request: Request, error: str = "", session: Session = session_dep,
                   user: str = user_dep):  # fmt: skip
        return listing(request, session, "others", error, user)

    @app.get("/repos")
    def tab_repos(request: Request, error: str = "", session: Session = session_dep,
                  user: str = user_dep):  # fmt: skip
        return listing(request, session, "repos", error, user)

    def listing(request: Request, session: Session, tab: str, error: str, user: str):
        """One tab's targets, as a table that sorts and searches."""
        now = utcnow()
        targets = [t for t in session.scalars(select(Target)) if category(t) == tab]
        rows = target_rows(session, targets)
        sorts = {"name": lambda r: r["target"].name, "score": score_of, "last": last_of,
                 "open": lambda r: tuple(r["sev"].get(s, 0) for s in SEVERITIES)}  # fmt: skip
        if tab == "ha":
            sorts["installed"] = lambda r: r["target"].installed_version
            sorts["kind"] = lambda r: r["target"].hacs_kind
            sorts["update"] = lambda r: (
                (r["offered"].score if r["offered"] else None) if r["target"].update_offered
                else None)  # fmt: skip
        elif tab == "others":
            sorts["kind"] = lambda r: r["target"].hacs_kind
        table = view(request.query_params, rows, sorts=sorts, default="name",
                     desc_first=("score", "last", "open", "update"), anchor="targets",
                     text=row_text)  # fmt: skip
        state = services(session, now)
        if error and error not in acquire.FORM_ERRORS:
            error = "That target couldn't be added."  # not text of ours: don't show it
        add_open = bool(error) or request.query_params.get("add") == "1"
        look, asked = chosen_look(request, "targets")
        cards = target_cards(session, table.rows) if look == "cards" else {}
        response = page(request, session, "listing.html", tab=tab, table=table, error=error,
                        add_open=add_open, add_source=request.query_params.get("source", ""),
                        profile=TAB_PROFILE.get(tab), state=state,
                        sync_counts=hass_sync.installed_counts(session) if tab == "ha" else {},
                        busy=sum(1 for r in rows if r["busy"]), look=look, cards=cards,
                        looks=look_links(request, "targets"), now=now, user=user)  # fmt: skip
        return remember_look(response, request, "targets", look) if asked else response

    def target_cards(session: Session, rows: list[dict]) -> dict[int, dict]:
        """What each target's card says: a sentence or two and a few chips, from its open
        findings and Barkley's report and plain words for the scan its grade is from."""
        ids = [r["target"].id for r in rows]
        open_by: dict[int, list[Finding]] = {}
        for f in session.scalars(select(Finding).where(Finding.status == "open",
                                                       Finding.target_id.in_(ids))):  # fmt: skip
            open_by.setdefault(f.target_id, []).append(f)
        cards = {}
        for row in rows:
            t, scan = row["target"], row["graded"]
            mine, plain = open_by.get(t.id, []), barkley_report.words(scan)
            cards[t.id] = {
                "sentence": barkley_report.card_sentence(t.profile, scan, mine, plain),
                "chips": barkley_report.card_chips(scan, mine, plain),
                "look": bool(attention(row)),
            }  # fmt: skip
        return cards

    @app.get("/system")
    def system(request: Request, session: Session = session_dep, user: str = user_dep):
        """The other services: Home Assistant, notifications, AI explanations; and exports."""
        now = utcnow()
        state = services(session, now)
        day = now - datetime.timedelta(hours=24)
        # By level, added up here: grouped by `level >= ERROR`, Postgres sees the two bound
        # ERRORs as different expressions and refuses the query (SQLite doesn't mind).
        logged = collections.Counter()
        for level, n in session.execute(
            select(LogEntry.level, func.count())
            .where(LogEntry.at >= day, LogEntry.level >= logging.WARNING)
            .group_by(LogEntry.level)):  # fmt: skip
            logged[level >= logging.ERROR] += n
        return page(request, session, "system.html", tab="system", state=state,
                    sync_counts=hass_sync.installed_counts(session), now=now, user=user,
                    log_errors=logged[True], log_warnings=logged[False],
                    log_days=settings.log_days)  # fmt: skip

    @app.get("/log")
    def log_page(request: Request, q: str = "", service: str = "", level: str = "",
                 before: int | None = None, session: Session = session_dep,
                 user: str = user_dep):  # fmt: skip
        """The services' log, newest first: searched, filtered by service and level, and
        paged back in time (`before`: the oldest message of the page before)."""
        q = " ".join(q.split())[:100]
        service = service if service in logs.SERVICES else ""
        level = level if level in LOG_LEVELS else ""
        query = select(LogEntry)
        for word in q.lower().split()[:8]:
            query = query.where(or_(func.lower(LogEntry.message).contains(word, autoescape=True),
                                    func.lower(LogEntry.logger).contains(word, autoescape=True)))
        if service:
            query = query.where(LogEntry.service == service)
        if level:
            query = query.where(LogEntry.level >= LOG_LEVELS[level])
        total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
        if before is not None:
            query = query.where(LogEntry.id < before)
        rows = session.scalars(query.order_by(LogEntry.id.desc()).limit(LOG_PAGE + 1)).all()
        filters = [(k, v) for k, v in (("q", q), ("service", service), ("level", level)) if v]
        older = (f"?{urlencode([*filters, ('before', rows[LOG_PAGE - 1].id)])}"
                 if len(rows) > LOG_PAGE else None)  # fmt: skip
        newest = f"?{urlencode(filters)}" if before is not None else None
        return page(request, session, "log.html", tab="system", rows=rows[:LOG_PAGE],
                    total=total, q=q, service=service, level=level, older=older,
                    newest=newest, services=logs.SERVICES, log_days=settings.log_days,
                    user=user)  # fmt: skip

    @app.post("/hass/sync")
    def request_sync(session: Session = session_dep, user: str = user_dep):
        hass_sync.status_row(session).requested_at = utcnow()
        session.commit()
        return RedirectResponse("/system", 303)

    @app.post("/notify/test")
    def request_test(session: Session = session_dep, user: str = user_dep):
        notify.state_row(session).test_requested_at = utcnow()
        session.commit()
        return RedirectResponse("/system", 303)

    @app.post("/targets")
    def add_target(
        name: str = Form(""),
        profile: str = Form(...),
        source: str = Form(...),
        ref: str = Form(""),
        interval_hours: int = Form(168),
        mine: str = Form(""),  # a repository: "1" for my code (a ticked box)
        session: Session = session_dep,
        user: str = user_dep,
    ):
        source, ref = source.strip(), ref.strip() or None
        mine_too = profile == "owned" and mine == "1"
        tab = ("code" if mine_too else "repos") if profile == "owned" else "others"
        try:
            if profile not in PROFILES:
                raise HTTPException(400, "Unknown profile.")
            if profile == "ha":
                source = acquire.normalize_ha_repo(source)
            else:
                acquire.validate_source(source, settings)
            acquire.validate_ref(ref)
        except acquire.AcquireError as exc:
            back = urlencode({"error": str(exc), "source": source[:300]})
            return RedirectResponse(f"/{tab}?{back}", 303)
        default = source.removesuffix("/").removesuffix(".git").rsplit("/", 1)[-1]
        target = Target(
            name=name.strip()[:200] or default,
            profile=profile,
            source=source,
            ref=ref,
            interval_hours=max(0, min(interval_hours, 24 * 90)),
            mine=mine_too,
        )
        session.add(target)
        session.commit()
        worker.enqueue(session, target, target.ref)
        return RedirectResponse(f"/targets/{target.id}", 303)

    @app.get("/marketplace")
    def marketplace(request: Request, q: str = "", kind: str = "", session: Session = session_dep,
                    user: str = user_dep):  # fmt: skip
        """Search the Marketplace catalog the hass-sync service last read."""
        q = " ".join(q.split())[:100]
        kind = kind if kind in ("integration", "card") else ""
        query = select(CatalogItem)
        for word in q.split()[:8]:
            like = "%" + word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            query = query.where(or_(CatalogItem.repo.ilike(like, escape="\\"),
                                    CatalogItem.name.ilike(like, escape="\\"),
                                    CatalogItem.description.ilike(like, escape="\\")))  # fmt: skip
        if kind:
            query = query.where(CatalogItem.kind == kind)
        total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
        items = session.scalars(query.order_by(CatalogItem.stars.desc(),
                                               func.lower(CatalogItem.name))
                                .limit(CATALOG_PAGE)).all()  # fmt: skip
        sources = [i.repo.lower() for i in items]
        targets = {
            t.source.lower(): t for t in session.scalars(select(Target).where(
                Target.profile == "ha", func.lower(Target.source).in_(sources)))
        }  # fmt: skip
        graded = {k: _graded(t.scans, None) for k, t in targets.items()}
        busy = {k for k, t in targets.items() if any(s.status in worker.ACTIVE for s in t.scans)}
        # The search itself is the query above (the whole catalog); this sorts what it found.
        table = view(request.query_params, items, anchor="catalog", default="stars",
                     default_desc=True, desc_first=("stars", "result"),
                     sorts={"name": lambda i: i.name, "version": lambda i: i.version,
                            "stars": lambda i: i.stars,
                            "result": lambda i: (g.score if (g := graded.get(i.repo.lower()))
                                                 else None)},
                     text=lambda i: [i.name, i.repo, i.description])  # fmt: skip
        return page(request, session, "marketplace.html", tab="marketplace", table=table,
                    total=total, q=q, kind=kind, targets=targets, graded=graded, busy=busy,
                    sync=session.get(HassSync, 1), shown=CATALOG_PAGE, user=user)  # fmt: skip

    @app.post("/marketplace/scan")
    def marketplace_scan(repo: str = Form(...), session: Session = session_dep,
                         user: str = user_dep):  # fmt: skip
        """Scan a catalog entry at the version the Marketplace would install. Only a repo
        in the catalog is accepted; it becomes an HA target that is rescanned only when
        asked (installing it makes hass-sync take it over)."""
        item = session.scalar(select(CatalogItem).where(CatalogItem.repo == repo))
        if item is None:
            raise HTTPException(404, "Not in the Marketplace catalog.")
        target = session.scalar(select(Target).where(
            Target.profile == "ha", func.lower(Target.source) == item.repo.lower()))  # fmt: skip
        if target is None:
            target = Target(name=item.name, profile="ha", source=item.repo,
                            hacs_kind=item.kind, interval_hours=0)  # fmt: skip
            session.add(target)
            session.commit()
        worker.enqueue(session, target, item.version)
        return RedirectResponse(f"/targets/{target.id}", 303)

    def download(body: str, media_type: str, name: str) -> Response:
        disposition = f'attachment; filename="{name}"'
        return Response(body, media_type=media_type,
                        headers={"Content-Disposition": disposition})  # fmt: skip

    def as_json(data) -> str:
        return json.dumps(data, indent=2, ensure_ascii=False)

    def export_scope(session: Session, tab: str, target: int | None) -> tuple[set | None, str]:
        """Which targets an export covers: one, a tab's, or all; and its file name part."""
        if target is not None:
            t = get_target(session, target)
            return {t.id}, t.name
        if tab in TABS:
            return {t.id for t in session.scalars(select(Target)) if category(t) == tab}, tab
        return None, "all"

    @app.get("/export.json")
    def export_everything(tab: str = "", session: Session = session_dep,
                          user: str = user_dep):  # fmt: skip
        only, name = export_scope(session, tab, None)
        return download(as_json(export.export_all(session, only)), "application/json",
                        export.filename(name, "json"))  # fmt: skip

    @app.get("/export/findings.csv")
    def export_csv(status: str = "", tab: str = "", target: int | None = None,
                   session: Session = session_dep, user: str = user_dep):  # fmt: skip
        status = status if status in ("open", "suppressed", "fixed") else ""
        only, name = export_scope(session, tab, target)
        return download(export.findings_csv(session, status or None, only),
                        "text/csv; charset=utf-8",
                        export.filename(f"{name}-findings-{status or 'all'}", "csv"))  # fmt: skip

    @app.get("/targets/{target_id}/export.json")
    def export_target_json(target_id: int, session: Session = session_dep,
                           user: str = user_dep):  # fmt: skip
        target = get_target(session, target_id)
        return download(as_json(export.export_target(session, target)), "application/json",
                        export.filename(target.name, "json"))  # fmt: skip

    @app.get("/targets/{target_id}/export.sarif")
    def export_target_sarif(target_id: int, session: Session = session_dep,
                            user: str = user_dep):  # fmt: skip
        target = get_target(session, target_id)
        return download(as_json(export.sarif(session, target)), "application/sarif+json",
                        export.filename(target.name, "sarif"))  # fmt: skip

    @app.get("/targets/{target_id}")
    def target_page(request: Request, target_id: int, status: str = "open", refresh: str = "1",
                    session: Session = session_dep, user: str = user_dep):  # fmt: skip
        target = get_target(session, target_id)
        status = status if status in ("open", "suppressed", "fixed") else "open"
        now = utcnow()
        live = progress(session, target.scans, now)
        counts = dict(
            session.execute(
                select(Finding.status, func.count())
                .where(Finding.target_id == target.id)
                .group_by(Finding.status)
            ).all()
        )
        found = session.scalars(
            select(Finding).where(Finding.target_id == target.id, Finding.status == status)
        ).all()
        # Rules suppressed in some files, and how many findings each keeps suppressed.
        covered = dict(session.execute(
            select(Finding.rule_suppression_id, func.count())
            .where(Finding.target_id == target.id, Finding.status == "suppressed",
                   Finding.rule_suppression_id.is_not(None))
            .group_by(Finding.rule_suppression_id)).all())  # fmt: skip
        why = None
        if target.profile == "owned":
            open_now = found if status == "open" else session.scalars(
                select(Finding).where(Finding.target_id == target.id,
                                      Finding.status == "open")).all()  # fmt: skip
            why = findings.issues(open_now)
        notes = ai.notes_for(session, "finding", (f.id for f in found))
        asking = any(n.status in ai.PENDING for n in notes.values())
        params = request.query_params
        table = view(params, found, anchor="findings", default="severity",
                     sorts={"severity": lambda f: (f.same_as is not None,
                                                   SEVERITY_RANK.get(f.severity, 9)),
                            "title": lambda f: f.title,
                            "where": lambda f: ((f.file or "").lower(), f.line or 0)
                            if f.file else None,
                            "scanner": lambda f: (f.scanner, f.rule_id),
                            "seen": lambda f: f.first_seen_at,
                            "last": lambda f: f.last_seen_at},
                     desc_first=("seen", "last"),
                     text=lambda f: [f.title, f.scanner, f.rule_id, f.file, f.severity,
                                     f.message, f.suppression_note])  # fmt: skip
        why_table = view(params, why or [], prefix="why_", anchor="grade",
                         default="points", default_desc=True,
                         desc_first=("points", "places"),
                         sorts={"severity": lambda i: SEVERITY_RANK.get(i.severity, 9),
                                "title": lambda i: i.title, "places": lambda i: i.count,
                                "points": lambda i: i.deduction},
                         text=lambda i: [i.title, i.scanner, i.rule_id, i.severity,
                                         *i.also])  # fmt: skip
        scans = view(params, target.scans[:25], prefix="scans_", anchor="scans",
                     default="id", default_desc=True, desc_first=("id", "score", "finished"),
                     sorts={"id": lambda s: s.id, "score": lambda s: s.score,
                            "version": lambda s: s.ref, "finished": lambda s: s.finished_at},
                     text=lambda s: [str(s.id), s.ref, s.commit_sha, s.verdict, s.status,
                                     s.kind])  # fmt: skip
        notifier = session.get(NotifyState, 1)
        tab = category(target)
        here = urlencode([(k, v) for k, v in params.multi_items() if k != "refresh"])
        # Ticking every open finding the table shows (after a search, say): no scripts.
        unticked = [(k, v) for k, v in params.multi_items() if k not in ("select", "refresh")]
        graded = _graded(target.scans, target.installed_version if tab == "ha" else None)
        shown = next((s for s in (graded, *target.scans)
                      if s is not None and s.status == "done" and s.report), None)  # fmt: skip
        look, asked = chosen_look(request, "findings")
        plain_by = {s.id: barkley_report.words(s) for s in target.scans if s.plain}
        said = {f.id: r for f in table.rows if f.scanner == "barkley" and (
            r := barkley_report.rule_words(plain_by.get(f.last_seen_scan_id, {}), f.rule_id))}
        response = page(request, session, "target.html", tab=tab, target=target, table=table,
                    look=look, looks=look_links(request, "findings"), said=said,
                    app=app_parts(shown, target.name), app_scan=shown,
                    picking=status == "open", ticked=params.get("select") == "all",
                    tick_all=f"?{urlencode([*unticked, ('select', 'all')])}#findings",
                    untick=f"?{urlencode(unticked)}#findings",
                    why_table=why_table, scans=scans, counts=counts, notes=notes,
                    rules={r.id: r for r in target.rule_suppressions}, covered=covered,
                    ai_on=ai.enabled(session),
                    notifier=notifier, defaults=(notifier.defaults if notifier else None) or {},
                    severities=SEVERITIES[:-1], status=status, progress=live, why=why,
                    deducted=sum(i.deduction for i in why or []),
                    latest=next((s for s in target.scans if s.status == "done"), None),
                    graded=graded,
                    refresh=bool(live or asking) and refresh != "0",
                    paused=bool(live or asking) and refresh == "0",
                    refresh_what=None if live else answering(session),
                    refresh_seconds=REFRESH_SECONDS, here=f"?{here}" if here else "?",
                    user=user)  # fmt: skip
        return remember_look(response, request, "findings", look) if asked else response

    @app.get("/findings/{finding_id}")
    def finding_page(request: Request, finding_id: int, refresh: str = "1",
                     session: Session = session_dep, user: str = user_dep):  # fmt: skip
        """One finding in full: the message, the code excerpt, the AI's explanation, and
        suppressing or reopening it."""
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(404)
        now = utcnow()
        note = ai.note_for(session, "finding", finding.id)
        asking = bool(note and note.status in ai.PENDING)
        alike = len(_alike(session, finding)) if finding.status == "open" else 0
        seen_in = (session.get(Scan, finding.last_seen_scan_id)
                   if finding.last_seen_scan_id else None)  # fmt: skip
        by_rule = (session.get(RuleSuppression, finding.rule_suppression_id)
                   if finding.rule_suppression_id else None)  # fmt: skip
        return page(request, session, "finding.html", tab=category(finding.target),
                    f=finding, target=finding.target, note=note, alike=alike, by_rule=by_rule,
                    twin=session.get(Finding, finding.same_as) if finding.same_as else None,
                    seen_in=seen_in, **explained(finding, seen_in, now),
                    ai_on=ai.enabled(session),
                    ai_limit=ai.limit_reached(session.get(AiState, 1), now),
                    refresh=asking and refresh != "0", paused=asking and refresh == "0",
                    refresh_what=answering(session), refresh_seconds=REFRESH_SECONDS,
                    here="?", now=now, user=user)  # fmt: skip

    def explained(finding: Finding, seen_in: Scan | None, now: datetime.datetime) -> dict:
        """A finding in plain words, beyond its scanner's message: what Barkley's panel says
        about its rule, the vulnerable package's fix and newer versions, the advisories,
        and what you can do."""
        owned = finding.target.profile == "owned"
        rule = (barkley_report.rule_words(barkley_report.words(seen_in), finding.rule_id)
                if finding.scanner == "barkley" else None)  # fmt: skip
        found = barkley_report.report_finding(seen_in.report if seen_in else None, finding)
        pkg = barkley_report.package((found or {}).get("dependency"), owned, now.date())
        bugs = pkg.bugs if pkg and pkg.bugs else barkley_report.bugs_of(finding.vulns)
        doc = (finding.details or {}).get("url")
        if doc and doc.lower() in {b.url.lower() for b in bugs}:
            doc = None  # osv-scanner's page for an advisory is the bug's own link
        return {"rule": rule, "pkg": pkg, "bugs": bugs,
                "action": barkley_report.package_action(pkg, owned) if pkg else None,
                "about": (finding.details or {}).get("about"), "doc": doc}

    def shared(session: Session, finding_id: int, explain: str) -> dict:
        """A finding as Markdown, with its AI explanation if one was asked for and there
        is one."""
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(404)
        note = ai.note_for(session, "finding", finding.id)
        if not (note and note.status == "done" and note.result):
            note = None
        include = note is not None and explain == "1"
        scan = session.get(Scan, finding.last_seen_scan_id) if finding.last_seen_scan_id else None
        body = export.finding_markdown(finding, scan, note if include else None)
        return {"f": finding, "target": finding.target, "note": note, "include": include,
                "body": body, "secret": finding.scanner in export.SECRET_SCANNERS}  # fmt: skip

    @app.get("/findings/{finding_id}/share")
    def share_finding(request: Request, finding_id: int, explain: str = "",
                      session: Session = session_dep, user: str = user_dep):  # fmt: skip
        """A finding as Markdown to copy, download, or take to a new GitHub issue."""
        s = shared(session, finding_id, explain)
        repo = export.github_repo(s["target"])
        issue, whole = (export.new_issue_url(repo, export.issue_title(s["f"]), s["body"])
                        if repo else (None, False))  # fmt: skip
        return page(request, session, "share.html", tab=category(s["target"]), repo=repo,
                    issue_url=issue, issue_whole=whole, now=utcnow(), user=user, **s)

    @app.get("/findings/{finding_id}/finding.md")
    def finding_markdown(finding_id: int, explain: str = "", session: Session = session_dep,
                         user: str = user_dep):  # fmt: skip
        s = shared(session, finding_id, explain)
        return download(s["body"], "text/markdown",
                        export.filename(f"{s['target'].name}-finding-{finding_id}", "md"))

    @app.post("/targets/{target_id}/scan")
    def scan_now(target_id: int, session: Session = session_dep, user: str = user_dep):
        target = get_target(session, target_id)
        worker.enqueue(session, target, target.ref)
        return RedirectResponse(f"/targets/{target_id}", 303)

    @app.post("/targets/{target_id}/watch")
    def target_watch(target_id: int, on: str = Form(...), session: Session = session_dep,
                     user: str = user_dep):  # fmt: skip
        """Scan each new commit on the branch, or don't."""
        target = get_target(session, target_id)
        if on not in ("on", "off") or target.profile != "owned":
            raise HTTPException(400)
        target.watch_commits = on == "on"
        target.head_checked_at = None  # look straight away
        session.commit()
        return RedirectResponse(f"/targets/{target_id}", 303)

    @app.post("/targets/{target_id}/mine")
    def target_mine(target_id: int, on: str = Form(...), session: Session = session_dep,
                    user: str = user_dep):  # fmt: skip
        """A repository is my code (Repositories › Mine), or someone else's (› Others)."""
        target = get_target(session, target_id)
        if on not in ("on", "off") or target.profile != "owned":
            raise HTTPException(400)
        target.mine = on == "on"
        session.commit()
        return RedirectResponse(f"/targets/{target_id}", 303)

    @app.post("/targets/{target_id}/notify")
    def target_notify(
        target_id: int,
        muted: str = Form(""),
        score_below: str = Form(""),
        min_severity: str = Form(""),
        clean_updates: str = Form(""),
        failures: str = Form(""),
        session: Session = session_dep,
        user: str = user_dep,
    ):
        """Blank means "use the notifier's default"."""
        target = get_target(session, target_id)

        def choice(value: str) -> bool | None:
            return {"on": True, "off": False}.get(value)

        score = score_below.strip()
        if score and not (score.isdigit() and 1 <= int(score) <= 100):
            raise HTTPException(400, "The score is a whole number from 1 to 100.")
        if min_severity and min_severity not in SEVERITIES[:-1]:  # not "info"
            raise HTTPException(400, "Unknown severity.")
        target.notify_muted = muted == "on"
        target.notify_score_below = int(score) if score else None
        target.notify_min_severity = min_severity or None
        target.notify_clean_updates = choice(clean_updates)
        target.notify_failures = choice(failures)
        session.commit()
        return RedirectResponse(f"/targets/{target_id}", 303)

    @app.post("/targets/{target_id}/delete")
    def delete_target(target_id: int, session: Session = session_dep, user: str = user_dep):
        target = get_target(session, target_id)
        tab = category(target)
        session.delete(target)
        session.commit()
        return RedirectResponse(f"/{tab}", 303)

    @app.get("/scans/{scan_id}")
    def scan_page(request: Request, scan_id: int, refresh: str = "1",
                  session: Session = session_dep, user: str = user_dep):  # fmt: skip
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(404)
        now = utcnow()
        live = progress(session, [scan], now)
        note = ai.note_for(session, "scan", scan.id)
        asking = bool(note and note.status in ai.PENDING)
        later = session.scalars(select(Scan).where(Scan.recheck_of == scan.id)
                                .order_by(Scan.id)).all()  # fmt: skip
        order = ("error", "skipped", "timeout", "ok", "not_applicable")
        runs = view(request.query_params, scan.scanner_runs or [], anchor="scanners",
                    default="name", desc_first=("findings",),
                    sorts={"name": lambda r: r.get("name"),
                           "state": lambda r: (order.index(r.get("state"))
                                               if r.get("state") in order else 9),
                           "findings": lambda r: r.get("findings")},
                    text=lambda r: [r.get("name"), r.get("state"), r.get("detail")])  # fmt: skip
        return page(request, session, "scan.html", tab=category(scan.target), scan=scan,
                    target=scan.target, progress=live, runs=runs,
                    base=session.get(Scan, scan.diff_from) if scan.diff_from else None,
                    rechecked=session.get(Scan, scan.recheck_of) if scan.recheck_of else None,
                    later=later, groups=DIFF_GROUPS, note=note, ai_on=ai.enabled(session),
                    app=app_parts(scan if scan.status == "done" else None, scan.target.name),
                    ai_limit=ai.limit_reached(session.get(AiState, 1), now),
                    refresh=bool(live or asking) and refresh != "0",
                    paused=bool(live or asking) and refresh == "0",
                    refresh_what=None if live else answering(session),
                    refresh_seconds=REFRESH_SECONDS, here="?", now=now,
                    user=user)  # fmt: skip

    @app.post("/scans/{scan_id}/recheck")
    def recheck_now(scan_id: int, session: Session = session_dep, user: str = user_dep):
        """Ask the runner to ask this scan's advisories again when it is next idle."""
        scan = session.get(Scan, scan_id)
        if scan is None or scan.barkley_id is None:
            raise HTTPException(404)
        scan.advisories_next_at = utcnow()
        session.commit()
        return RedirectResponse(f"/scans/{scan_id}", 303)

    @app.post("/scans/{scan_id}/review")
    def review_scan(scan_id: int, session: Session = session_dep, user: str = user_dep):
        """Ask the model to review this scan's result (the ai service answers)."""
        scan = session.get(Scan, scan_id)
        if scan is None or scan.status != "done":
            raise HTTPException(404)
        if not ai.enabled(session):
            raise HTTPException(409, "AI explanations are off.")
        ai.request(session, "scan", scan.id, scan.target_id, user)
        return RedirectResponse(f"/scans/{scan_id}#review", 303)

    @app.post("/findings/{finding_id}/explain")
    def explain_finding(finding_id: int, session: Session = session_dep, user: str = user_dep):
        """Ask the model to explain this finding (the ai service answers)."""
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(404)
        if not ai.enabled(session):
            raise HTTPException(409, "AI explanations are off.")
        ai.request(session, "finding", finding.id, finding.target_id, user)
        return RedirectResponse(f"/findings/{finding.id}#explain", 303)

    @app.post("/findings/{finding_id}/suppress")
    def suppress(
        finding_id: int,
        reason: str = Form(...),
        note: str = Form(...),
        days: int = Form(DEFAULT_SUPPRESSION_DAYS),
        same_rule: str = Form(""),  # also the target's other open findings from this rule
        session: Session = session_dep,
        user: str = user_dep,
    ):
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(404)
        problem = suppression_problem(reason, days)
        if problem or not note.strip():
            raise HTTPException(400, problem or "A suppression needs a reason and a justification.")
        chosen = [finding, *(_alike(session, finding) if same_rule else [])]
        suppress_findings([(f, note) for f in chosen], reason, days, user)
        session.commit()
        return RedirectResponse(f"/targets/{finding.target_id}#findings", 303)

    def _alike(session: Session, finding: Finding) -> list[Finding]:
        """The target's other open findings from the same scanner and rule."""
        return list(session.scalars(select(Finding).where(
            Finding.target_id == finding.target_id, Finding.status == "open",
            Finding.scanner == finding.scanner, Finding.rule_id == finding.rule_id,
            Finding.id != finding.id)))  # fmt: skip

    def _picked(session: Session, target: Target, ids: list[int]) -> list[Finding]:
        """The target's open findings among `ids`, the worst first. Other ids (another
        target's, or no longer open) are left out."""
        if not ids:
            return []
        found = session.scalars(select(Finding).where(
            Finding.target_id == target.id, Finding.status == "open",
            Finding.id.in_(ids[:PICK_MAX]))).all()  # fmt: skip
        return sorted(found, key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.scanner,
                                            f.rule_id, f.file or "", f.line or 0))  # fmt: skip

    @app.get("/targets/{target_id}/suppress")
    def suppress_many_page(request: Request, target_id: int,
                           ids: Annotated[list[int] | None, Query()] = None,
                           session: Session = session_dep, user: str = user_dep):  # fmt: skip
        """Suppressing the findings ticked on the target's page: one reason, and one note
        for all of them or one of its own for each."""
        target = get_target(session, target_id)
        return page(request, session, "suppress.html", tab=category(target), target=target,
                    found=_picked(session, target, ids or []), reason="", note="",
                    days=DEFAULT_SUPPRESSION_DAYS, own={}, problem="", user=user)  # fmt: skip

    @app.post("/targets/{target_id}/suppress")
    def suppress_many(request: Request, target_id: int,
                      ids: Annotated[list[int] | None, Form()] = None,
                      notes: Annotated[list[str] | None, Form()] = None,
                      reason: str = Form(""), note: str = Form(""),
                      days: int = Form(DEFAULT_SUPPRESSION_DAYS),
                      session: Session = session_dep, user: str = user_dep):  # fmt: skip
        """Each ticked finding comes with its own note field (`notes`, in the same order as
        `ids`): left empty, the note for all of them stands."""
        target = get_target(session, target_id)
        ids, notes = ids or [], notes or []
        if len(notes) != len(ids):
            raise HTTPException(400, "Each finding comes with a field for its own note.")
        own = {i: n.strip()[:2000] for i, n in zip(ids, notes, strict=True)}
        found = _picked(session, target, ids)
        problem = suppression_problem(reason, days)
        if not found:
            problem = "None of these findings is open any more."
        elif not problem and (bare := sum(not (own.get(f.id) or note.strip()) for f in found)):
            problem = (f"{bare} of them {'has' if bare == 1 else 'have'} no note: write one "
                       "for all of them, or one for each.")
        if problem:  # the page again, with what was written; nothing is suppressed
            response = page(request, session, "suppress.html", tab=category(target),
                            target=target, found=found, reason=reason, note=note, days=days,
                            own=own, problem=problem, user=user)  # fmt: skip
            response.status_code = 400
            return response
        suppress_findings([(f, own.get(f.id) or note) for f in found], reason, days, user)
        session.commit()
        return RedirectResponse(f"/targets/{target.id}#findings", 303)

    @app.post("/findings/{finding_id}/reopen")
    def reopen(finding_id: int, session: Session = session_dep, user: str = user_dep):
        """Open again, on its own: a rule suppression that covered it leaves it open."""
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(404)
        finding.status, finding.suppressed_until, finding.fixed_at = "open", None, None
        finding.rule_suppression_id = None
        session.commit()
        return RedirectResponse(f"/findings/{finding.id}", 303)

    # --- a rule suppressed in some files ---------------------------------------------

    def _with_file(session: Session, finding_id: int) -> Finding:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(404)
        if not finding.file:
            raise HTTPException(400, "This finding names no file to go by.")
        return finding

    def _rule_matches(session: Session, finding: Finding, pattern: str) -> list[Finding]:
        """The target's open findings from this finding's scanner and rule, in files that
        match the pattern."""
        found = session.scalars(select(Finding).where(
            Finding.target_id == finding.target_id, Finding.status == "open",
            Finding.scanner == finding.scanner, Finding.rule_id == finding.rule_id))  # fmt: skip
        return sorted((f for f in found if findings.path_matches(pattern, f.file)),
                      key=lambda f: (f.file or "", f.line or 0))  # fmt: skip

    def _pattern_problem(session: Session, finding: Finding, tidy: str | None) -> str | None:
        if tidy is None:
            return ("Name a folder or some files: tests/, say, or src/**/*.html. A rule "
                    "can't be suppressed in every file of a repository.")
        if not findings.path_matches(tidy, finding.file):
            return f"That doesn't take in this finding's own file, {finding.file}."
        now = utcnow()
        if any(r.scanner == finding.scanner and r.rule_id == finding.rule_id
               and r.pattern == tidy and r.active(now)
               for r in finding.target.rule_suppressions):  # fmt: skip
            return f"This rule is already suppressed in files matching {tidy}."
        return None

    def _rule_page(request: Request, session: Session, finding: Finding, pattern: str,
                   user: str, *, reason: str = "", note: str = "",
                   days: int = DEFAULT_SUPPRESSION_DAYS, problem: str | None = None):  # fmt: skip
        tidy = findings.path_pattern(pattern)
        wrong = _pattern_problem(session, finding, tidy)
        matched = _rule_matches(session, finding, tidy) if tidy else []
        return page(request, session, "suppress_rule.html", tab=category(finding.target),
                    target=finding.target, f=finding, pattern=pattern, tidy=tidy,
                    wrong=wrong, problem=problem, matched=matched, reason=reason, note=note,
                    days=days, user=user)  # fmt: skip

    @app.get("/findings/{finding_id}/suppress-rule")
    def suppress_rule_page(request: Request, finding_id: int, pattern: str | None = None,
                           session: Session = session_dep, user: str = user_dep):  # fmt: skip
        """Suppressing a finding's rule in a folder or some files, now and in later scans:
        the pattern is checked, showing the open findings it takes in, before anything is
        suppressed."""
        finding = _with_file(session, finding_id)
        written = folder_of(finding.file or "") if pattern is None else pattern
        return _rule_page(request, session, finding, written, user)

    @app.post("/findings/{finding_id}/suppress-rule")
    def suppress_rule(request: Request, finding_id: int, pattern: str = Form(""),
                      reason: str = Form(""), note: str = Form(""),
                      days: int = Form(DEFAULT_SUPPRESSION_DAYS),
                      session: Session = session_dep, user: str = user_dep):  # fmt: skip
        finding = _with_file(session, finding_id)
        tidy = findings.path_pattern(pattern)
        problem = (_pattern_problem(session, finding, tidy) or suppression_problem(reason, days)
                   or (None if note.strip() else "Say why: a suppression needs a note."))
        if problem:  # the page again, with what was written; nothing is suppressed
            response = _rule_page(request, session, finding, pattern, user, reason=reason,
                                  note=note, days=days, problem=problem)  # fmt: skip
            response.status_code = 400
            return response
        rule = RuleSuppression(target_id=finding.target_id, scanner=finding.scanner,
                               rule_id=finding.rule_id, pattern=tidy, reason=reason,
                               note=note.strip()[:2000], created_by=user,
                               until=suppression_until(days))  # fmt: skip
        session.add(rule)
        session.flush()
        for f in _rule_matches(session, finding, tidy or ""):
            findings.suppress_by_rule(f, rule)
        session.commit()
        return RedirectResponse(f"/targets/{finding.target_id}#rules", 303)

    @app.post("/rule-suppressions/{rule_id}/remove")
    def remove_rule_suppression(rule_id: int, session: Session = session_dep,
                                user: str = user_dep):  # fmt: skip
        """Stop suppressing a rule in those files: the findings it suppressed open again
        (unless another of the target's rule suppressions takes them in), and the next
        scans leave new ones open."""
        rule = session.get(RuleSuppression, rule_id)
        if rule is None:
            raise HTTPException(404)
        now = utcnow()
        others = session.scalars(select(RuleSuppression).where(
            RuleSuppression.target_id == rule.target_id, RuleSuppression.id != rule.id)
            .order_by(RuleSuppression.id)).all()  # fmt: skip
        for f in session.scalars(select(Finding).where(Finding.rule_suppression_id == rule.id)):
            if f.status != "suppressed":
                f.rule_suppression_id = None
            elif other := next((r for r in others if findings.covers(r, f, now)), None):
                findings.suppress_by_rule(f, other)
            else:
                f.status, f.suppressed_until, f.rule_suppression_id = "open", None, None
        target_id = rule.target_id
        session.delete(rule)
        session.commit()
        return RedirectResponse(f"/targets/{target_id}#rules", 303)

    return app
