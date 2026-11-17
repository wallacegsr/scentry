"""The portal. Server-rendered, no JavaScript: the content security policy allows no
scripts at all, because the pages show text taken from scanned code."""

from __future__ import annotations

import base64
import binascii
import datetime
import ipaddress
import json
import secrets
from pathlib import Path
from urllib.parse import quote, urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from scentry import __version__, acquire, db, export, findings, hass_sync, notify, worker
from scentry.config import Settings, get_settings
from scentry.findings import DEFAULT_SUPPRESSION_DAYS, SUPPRESSION_REASONS
from scentry.models import (
    PROFILES,
    SEVERITY_RANK,
    Finding,
    HassSync,
    NotifyState,
    Scan,
    Target,
    utcnow,
)

HERE = Path(__file__).parent
CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)


def _graded(scans: list[Scan], version: str | None) -> Scan | None:
    """The newest finished scan with a result: of `version` when one is given (what is
    installed), otherwise of anything."""
    for scan in scans:
        if scan.status == "done" and scan.verdict and (version is None or scan.ref == version):
            return scan
    return None


REFRESH_SECONDS = 10


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


def _trusted(host: str, cidrs: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(c, strict=False) for c in cidrs)


def make_auth(settings: Settings):
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
            try:
                user, _, password = base64.b64decode(value).decode("utf-8").partition(":")
            except (binascii.Error, UnicodeDecodeError):
                user = password = ""
            user_ok = secrets.compare_digest(user.encode(), settings.admin_user.encode())
            pass_ok = secrets.compare_digest(password.encode(), settings.admin_password.encode())
            if user_ok and pass_ok:
                return user
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

    def page(request: Request, name: str, **context):
        return templates.TemplateResponse(request, name, context)

    def get_target(session: Session, target_id: int) -> Target:
        target = session.get(Target, target_id)
        if target is None:
            raise HTTPException(404)
        return target

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return PlainTextResponse("ok")

    @app.get("/")
    def index(request: Request, error: str = "", session: Session = session_dep,
              user: str = user_dep):  # fmt: skip
        open_counts = dict(
            session.execute(
                select(Finding.target_id, func.count())
                .where(Finding.status == "open")
                .group_by(Finding.target_id)
            ).all()
        )
        sections: dict[str, list[dict]] = {"installed": [], "owned": [], "ha": []}
        for target in session.scalars(select(Target).order_by(func.lower(Target.name))):
            scans = target.scans  # newest first
            installed = target.origin == "hacs" and target.hacs_removed_at is None
            row = {
                "target": target,
                "busy": [s for s in scans if s.status in worker.ACTIVE],
                "graded": _graded(scans, target.installed_version if installed else None),
                "offered": (
                    next((s for s in scans if s.ref == target.available_version), None)
                    if installed and target.update_offered else None
                ),
                "open": open_counts.get(target.id, 0),
            }  # fmt: skip
            key = "installed" if installed else target.profile
            sections[key].append(row)
        sync = session.get(HassSync, 1)
        now = utcnow()
        notifier = session.get(NotifyState, 1)
        notifier_gone = bool(
            notifier and notifier.services
            and (notifier.seen_at is None or now - notifier.seen_at > notify.HEARTBEAT)
        )  # fmt: skip
        waiting = session.execute(
            select(func.count(), func.max(Scan.not_before))
            .where(Scan.status == "queued", Scan.not_before > now)
        ).one()  # fmt: skip
        return page(request, "index.html", sections=sections, error=error, profiles=PROFILES,
                    sync=sync, sync_counts=hass_sync.installed_counts(session),
                    notifier=notifier, notifier_gone=notifier_gone, waiting=waiting,
                    now=now, user=user)  # fmt: skip

    @app.post("/hass/sync")
    def request_sync(session: Session = session_dep, user: str = user_dep):
        hass_sync.status_row(session).requested_at = utcnow()
        session.commit()
        return RedirectResponse("/", 303)

    @app.post("/notify/test")
    def request_test(session: Session = session_dep, user: str = user_dep):
        notify.state_row(session).test_requested_at = utcnow()
        session.commit()
        return RedirectResponse("/", 303)

    @app.post("/targets")
    def add_target(
        name: str = Form(""),
        profile: str = Form(...),
        source: str = Form(...),
        ref: str = Form(""),
        interval_hours: int = Form(168),
        session: Session = session_dep,
        user: str = user_dep,
    ):
        source, ref = source.strip(), ref.strip() or None
        try:
            if profile not in PROFILES:
                raise acquire.AcquireError("Unknown profile.")
            if profile == "ha":
                source = acquire.normalize_ha_repo(source)
            else:
                acquire.validate_source(source, settings)
            acquire.validate_ref(ref)
        except acquire.AcquireError as exc:
            return RedirectResponse(f"/?error={quote(str(exc))}", 303)
        default = source.removesuffix("/").removesuffix(".git").rsplit("/", 1)[-1]
        target = Target(
            name=name.strip()[:200] or default,
            profile=profile,
            source=source,
            ref=ref,
            interval_hours=max(0, min(interval_hours, 24 * 90)),
        )
        session.add(target)
        session.commit()
        worker.enqueue(session, target, target.ref)
        return RedirectResponse(f"/targets/{target.id}", 303)

    def download(body: str, media_type: str, name: str) -> Response:
        disposition = f'attachment; filename="{name}"'
        return Response(body, media_type=media_type,
                        headers={"Content-Disposition": disposition})  # fmt: skip

    def as_json(data) -> str:
        return json.dumps(data, indent=2, ensure_ascii=False)

    @app.get("/export.json")
    def export_everything(session: Session = session_dep, user: str = user_dep):
        return download(as_json(export.export_all(session)), "application/json",
                        export.filename("all", "json"))  # fmt: skip

    @app.get("/export/findings.csv")
    def export_csv(status: str = "", session: Session = session_dep, user: str = user_dep):
        status = status if status in ("open", "suppressed", "fixed") else ""
        return download(export.findings_csv(session, status or None), "text/csv; charset=utf-8",
                        export.filename(f"findings-{status or 'all'}", "csv"))  # fmt: skip

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
        found.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.scanner, f.file or ""))
        why = None
        if target.profile == "owned":
            open_now = found if status == "open" else session.scalars(
                select(Finding).where(Finding.target_id == target.id,
                                      Finding.status == "open")).all()  # fmt: skip
            why = findings.issues(open_now)
        return page(request, "target.html", target=target, findings=found, counts=counts,
                    status=status, scans=target.scans[:10], progress=live, why=why,
                    deducted=sum(i.deduction for i in why or []),
                    latest=next((s for s in target.scans if s.status == "done"), None),
                    refresh=bool(live) and refresh != "0", paused=bool(live) and refresh == "0",
                    refresh_seconds=REFRESH_SECONDS, here=f"?status={quote(status)}",
                    user=user)  # fmt: skip

    @app.post("/targets/{target_id}/scan")
    def scan_now(target_id: int, session: Session = session_dep, user: str = user_dep):
        target = get_target(session, target_id)
        worker.enqueue(session, target, target.ref)
        return RedirectResponse(f"/targets/{target_id}", 303)

    @app.post("/targets/{target_id}/delete")
    def delete_target(target_id: int, session: Session = session_dep, user: str = user_dep):
        session.delete(get_target(session, target_id))
        session.commit()
        return RedirectResponse("/", 303)

    @app.get("/scans/{scan_id}")
    def scan_page(request: Request, scan_id: int, refresh: str = "1",
                  session: Session = session_dep, user: str = user_dep):  # fmt: skip
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(404)
        live = progress(session, [scan], utcnow())
        return page(request, "scan.html", scan=scan, target=scan.target, progress=live,
                    refresh=bool(live) and refresh != "0", paused=bool(live) and refresh == "0",
                    refresh_seconds=REFRESH_SECONDS, here="?", user=user)  # fmt: skip

    @app.post("/findings/{finding_id}/suppress")
    def suppress(
        finding_id: int,
        reason: str = Form(...),
        note: str = Form(...),
        days: int = Form(DEFAULT_SUPPRESSION_DAYS),
        session: Session = session_dep,
        user: str = user_dep,
    ):
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(404)
        if reason not in SUPPRESSION_REASONS or not note.strip():
            raise HTTPException(400, "A suppression needs a reason and a justification.")
        finding.status = "suppressed"
        finding.suppression_reason, finding.suppression_note = reason, note.strip()[:2000]
        finding.suppressed_by = user
        # 0 days = permanent; anything else comes back for review when it expires.
        finding.suppressed_until = (
            utcnow() + datetime.timedelta(days=min(days, 3650)) if days > 0 else None
        )
        session.commit()
        return RedirectResponse(f"/targets/{finding.target_id}", 303)

    @app.post("/findings/{finding_id}/reopen")
    def reopen(finding_id: int, session: Session = session_dep, user: str = user_dep):
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(404)
        finding.status, finding.suppressed_until, finding.fixed_at = "open", None, None
        session.commit()
        return RedirectResponse(f"/targets/{finding.target_id}", 303)

    return app
