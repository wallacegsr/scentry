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

from scentry import __version__, acquire, ai, db, export, findings, hass_sync, notify, worker
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
CATALOG_PAGE = 50  # search results shown
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
        ai_state = session.get(AiState, 1)
        ai_gone = bool(ai_state and ai_state.configured and (
            ai_state.seen_at is None or now - ai_state.seen_at > ai.HEARTBEAT))  # fmt: skip
        waiting = session.execute(
            select(func.count(), func.max(Scan.not_before))
            .where(Scan.status == "queued", Scan.not_before > now)
        ).one()  # fmt: skip
        return page(request, "index.html", sections=sections, error=error, profiles=PROFILES,
                    sync=sync, sync_counts=hass_sync.installed_counts(session),
                    notifier=notifier, notifier_gone=notifier_gone, waiting=waiting,
                    ai_state=ai_state, ai_gone=ai_gone,
                    ai_limit=ai.limit_reached(ai_state, now), now=now, user=user)  # fmt: skip

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
        return page(request, "marketplace.html", items=items, total=total, q=q, kind=kind,
                    targets=targets, graded=graded, busy=busy,
                    sync=session.get(HassSync, 1), now=utcnow(),
                    shown=CATALOG_PAGE, user=user)  # fmt: skip

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
        found.sort(key=lambda f: (f.same_as is not None, SEVERITY_RANK.get(f.severity, 9),
                                  f.scanner, f.file or ""))  # fmt: skip
        twin_of = {f.id: f for f in session.scalars(select(Finding).where(
            Finding.id.in_({f.same_as for f in found if f.same_as is not None})))}  # fmt: skip
        why = None
        if target.profile == "owned":
            open_now = found if status == "open" else session.scalars(
                select(Finding).where(Finding.target_id == target.id,
                                      Finding.status == "open")).all()  # fmt: skip
            why = findings.issues(open_now)
        notifier = session.get(NotifyState, 1)
        notes = ai.notes_for(session, "finding", (f.id for f in found))
        asking = any(n.status in ai.PENDING for n in notes.values())
        return page(request, "target.html", target=target, findings=found, counts=counts,
                    twin_of=twin_of, notes=notes, ai_on=ai.enabled(session),
                    ai_limit=ai.limit_reached(session.get(AiState, 1), now),
                    notifier=notifier, defaults=(notifier.defaults if notifier else None) or {},
                    severities=SEVERITIES[:-1],
                    status=status, scans=target.scans[:10], progress=live, why=why,
                    deducted=sum(i.deduction for i in why or []),
                    latest=next((s for s in target.scans if s.status == "done"), None),
                    refresh=bool(live or asking) and refresh != "0",
                    paused=bool(live or asking) and refresh == "0",
                    refresh_what=None if live else "Claude is answering",
                    refresh_seconds=REFRESH_SECONDS, here=f"?status={quote(status)}",
                    user=user)  # fmt: skip

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
        session.delete(get_target(session, target_id))
        session.commit()
        return RedirectResponse("/", 303)

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
        return page(request, "scan.html", scan=scan, target=scan.target, progress=live,
                    base=session.get(Scan, scan.diff_from) if scan.diff_from else None,
                    rechecked=session.get(Scan, scan.recheck_of) if scan.recheck_of else None,
                    later=later, groups=DIFF_GROUPS, note=note, ai_on=ai.enabled(session),
                    ai_limit=ai.limit_reached(session.get(AiState, 1), now),
                    refresh=bool(live or asking) and refresh != "0",
                    paused=bool(live or asking) and refresh == "0",
                    refresh_what=None if live else "Claude is answering",
                    refresh_seconds=REFRESH_SECONDS, here="?", user=user)  # fmt: skip

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
        """Ask Claude to review this scan's result (the ai service answers)."""
        scan = session.get(Scan, scan_id)
        if scan is None or scan.status != "done":
            raise HTTPException(404)
        if not ai.enabled(session):
            raise HTTPException(409, "AI explanations are off.")
        ai.request(session, "scan", scan.id, scan.target_id, user)
        return RedirectResponse(f"/scans/{scan_id}#review", 303)

    @app.post("/findings/{finding_id}/explain")
    def explain_finding(finding_id: int, session: Session = session_dep, user: str = user_dep):
        """Ask Claude to explain this finding (the ai service answers)."""
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise HTTPException(404)
        if not ai.enabled(session):
            raise HTTPException(409, "AI explanations are off.")
        ai.request(session, "finding", finding.id, finding.target_id, user)
        return RedirectResponse(f"/targets/{finding.target_id}?status={quote(finding.status)}"
                                f"#f{finding.id}", 303)  # fmt: skip

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
