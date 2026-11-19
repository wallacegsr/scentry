from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scentry import db
from scentry.config import Settings
from scentry.models import Finding, Scan, Target
from scentry.web.app import SignInLimit, create_app

AUTH = ("admin", "pw")


def make(tmp_path, **overrides):
    settings = Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'web.db'}",
                        admin_password="pw", **overrides)  # fmt: skip
    return TestClient(create_app(settings), follow_redirects=False)


@pytest.fixture
def client(tmp_path):
    return make(tmp_path)


def test_sign_in_required(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/").status_code == 401
    assert client.get("/", auth=("admin", "wrong")).status_code == 401
    ok = client.get("/", auth=AUTH)
    assert ok.status_code == 200
    assert "script-src" not in ok.headers["content-security-policy"]
    assert "default-src 'none'" in ok.headers["content-security-policy"]


def test_wrong_passwords_are_limited(client):
    limit = SignInLimit.LIMIT
    for _ in range(limit):
        assert client.get("/", auth=("admin", "guess")).status_code == 401
    r = client.get("/", auth=AUTH)  # the right one too, from that address, for a while
    assert r.status_code == 429 and 0 < int(r.headers["retry-after"]) <= SignInLimit.WINDOW + 1
    assert client.get("/").status_code == 401  # no password: still asked for one


def test_sign_in_limit_window():
    limit = SignInLimit()
    for i in range(limit.LIMIT):
        limit.failed("a", now=100.0 + i)
    assert limit.wait("b", now=200.0) == 0
    assert limit.wait("a", now=200.0) == limit.WINDOW - 100 + 1
    assert limit.wait("a", now=100.0 + limit.WINDOW) == 0  # the first has aged out


def test_refuses_to_start_without_a_password(tmp_path):
    with pytest.raises(RuntimeError):
        create_app(Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'x.db'}"))


def test_proxy_mode_trusts_only_the_proxy(tmp_path):
    untrusted = make(tmp_path, auth_mode="proxy", trusted_proxies=["10.0.0.0/8"])
    assert untrusted.get("/", headers={"Remote-User": "eve"}).status_code == 403


def test_add_target_queues_a_scan_and_escapes_untrusted_text(client):
    r = client.post("/targets", auth=AUTH, data={"profile": "ha",
                    "source": "https://github.com/owner/repo", "ref": "", "name": ""})  # fmt: skip
    assert r.status_code == 303 and r.headers["location"] == "/targets/1"
    with db.SessionLocal() as s:
        target = s.get(Target, 1)
        assert (target.source, target.name) == ("owner/repo", "repo")
        assert s.scalar(select(Scan)).status == "queued"
        s.add(Finding(target_id=1, fingerprint="f", scanner="barkley", rule_id="r",
                      title="<script>alert(1)</script>", severity="high",
                      evidence="<img src=x onerror=1>"))  # fmt: skip
        s.commit()
    page = client.get("/targets/1", auth=AUTH).text
    assert "<script>" not in page and "&lt;script&gt;" in page
    assert "<img src=x" not in page
    assert "owner/repo" in client.get("/others", auth=AUTH).text
    finding = client.get("/findings/1", auth=AUTH).text
    assert "<script>" not in finding and "&lt;img src=x" in finding


def test_bad_target_and_cross_site_post(client):
    r = client.post("/targets", auth=AUTH, data={"profile": "owned", "source": "http://x/y",
                                                 "mine": "1"})  # fmt: skip
    assert r.status_code == 303 and r.headers["location"].startswith("/code?error=")
    # Back on its tab: the mistake, and the form again with what was typed.
    page = client.get(r.headers["location"], auth=AUTH).text
    assert "clone URL" in page and 'value="http://x/y"' in page
    assert 'name="mine" value="1" checked' in page
    r = client.post("/targets", auth=AUTH, data={"profile": "owned", "source": "http://x/y"})
    assert r.headers["location"].startswith("/repos?error=")  # not ticked: someone else's
    page = client.get(r.headers["location"], auth=AUTH).text
    assert 'name="mine" value="1">' in page  # and the box stays unticked
    r = client.post("/targets", auth=AUTH, data={"profile": "ha", "source": "not a repo"})
    assert r.headers["location"].startswith("/others?error=")
    # A crafted link can't put its own words on the page.
    page = client.get("/code?error=Session+expired:+sign+in+at+evil.example", auth=AUTH).text
    assert "evil.example" not in page and "That target couldn&#39;t be added." in page
    r = client.post("/targets", auth=AUTH, data={"profile": "ha", "source": "a/b"},
                    headers={"Sec-Fetch-Site": "cross-site"})  # fmt: skip
    assert r.status_code == 403
    r = client.post("/targets", auth=AUTH, data={"profile": "ha", "source": "a/b"},
                    headers={"Origin": "https://evil.example"})  # fmt: skip
    assert r.status_code == 403
    r = client.post("/targets", auth=AUTH, data={"profile": "ha", "source": "a/b"},
                    headers={"Origin": "null"})  # fmt: skip
    assert r.status_code == 403  # an older browser that won't say where it comes from


def test_own_forms_accepted_as_browsers_send_them(client):
    # What a current browser sends for the portal's own form, including the "Origin:
    # null" it sends under a strict referrer policy.
    for origin in ("http://testserver", "null"):
        r = client.post("/targets", auth=AUTH, data={"profile": "ha", "source": "a/b"},
                        headers={"Sec-Fetch-Site": "same-origin", "Origin": origin})  # fmt: skip
        assert r.status_code == 303, origin
    r = client.post("/targets", auth=AUTH, data={"profile": "ha", "source": "a/b"},
                    headers={"Sec-Fetch-Site": "same-site", "Origin": "null"})  # fmt: skip
    assert r.status_code == 403
    assert client.get("/", auth=AUTH).headers["referrer-policy"] == "same-origin"


def test_suppress_and_reopen(client):
    client.post("/targets", auth=AUTH, data={"profile": "ha", "source": "a/b"})
    with db.SessionLocal() as s:
        s.add(Finding(target_id=1, fingerprint="f", scanner="x", rule_id="r", title="t",
                      severity="low"))  # fmt: skip
        s.commit()
    bad = client.post("/findings/1/suppress", auth=AUTH, data={"reason": "nope", "note": "n"})
    assert bad.status_code == 400
    negative = {"reason": "false_positive", "note": "n", "days": "-5"}
    assert client.post("/findings/1/suppress", auth=AUTH, data=negative).status_code == 400
    form = {"reason": "false_positive", "note": "test fixture", "days": "30"}
    ok = client.post("/findings/1/suppress", auth=AUTH, data=form)
    assert ok.status_code == 303
    with db.SessionLocal() as s:
        f = s.get(Finding, 1)
        assert (f.status, f.suppressed_by) == ("suppressed", "admin")
        assert f.suppressed_until is not None
    assert "test fixture" in client.get("/targets/1?status=suppressed", auth=AUTH).text
    client.post("/findings/1/reopen", auth=AUTH)
    with db.SessionLocal() as s:
        assert s.get(Finding, 1).status == "open"


def test_installed_section_and_sync_button(client):
    from scentry.models import HassSync, utcnow

    assert "Sync now" not in client.get("/ha", auth=AUTH).text  # sync not configured
    with db.SessionLocal() as s:
        s.add(HassSync(id=1, last_ok_at=utcnow(), ha_version="2026.11.2", installed=1,
                       skipped={"theme": 2}, listening=True))  # fmt: skip
        t = Target(name="Weather", profile="ha", source="a/weather", origin="hacs",
                   hacs_kind="integration", installed_version="1.0.0",
                   available_version="1.1.0", ref="1.0.0")  # fmt: skip
        s.add(t)
        s.flush()
        s.add(Scan(target_id=t.id, ref="1.0.0", status="done", score=95, verdict="Good Boy",
                   complete=True, finished_at=utcnow()))  # fmt: skip
        s.add(Scan(target_id=t.id, ref="1.1.0", status="done", score=30,
                   verdict="BORK BORK BORK", complete=True, finished_at=utcnow()))  # fmt: skip
        s.commit()
    page = client.get("/ha", auth=AUTH).text
    assert "1 installed" in page and "Home Assistant 2026.11.2" in page
    assert "2 theme" in page and "watching for installs" in page
    assert page.index("Good Boy") < page.index("BORK BORK BORK")  # installed, then offered
    # The update scores far lower than what is installed: the overview says so.
    overview = client.get("/", auth=AUTH).text
    assert "Needs a look" in overview and "update 1.1.0 scores 30" in overview
    assert client.post("/hass/sync", auth=AUTH).headers["location"] == "/system"
    with db.SessionLocal() as s:
        assert s.get(HassSync, 1).requested_at is not None
    assert "Sync requested" in client.get("/ha", auth=AUTH).text
    assert "Sync requested" in client.get("/system", auth=AUTH).text


def test_marketplace_search_and_scan(client):
    from scentry.models import CatalogItem, HassSync, utcnow

    assert "the sync is connected" in client.get("/marketplace", auth=AUTH).text
    with db.SessionLocal() as s:
        s.add(HassSync(id=1, last_ok_at=utcnow(), catalog_size=3, catalog_at=utcnow()))
        s.add_all([
            CatalogItem(repo="a/weather", kind="integration", name="Weather", stars=50,
                        description="Forecasts <b>now</b>", version="v2.0"),
            CatalogItem(repo="b/clock", kind="card", name="Clock_Card", stars=900,
                        description="A 100% clock"),
            CatalogItem(repo="c/forecast-card", kind="card", name="Forecast", stars=5,
                        description="weather on a card", version="1.0"),
        ])  # fmt: skip
        s.commit()
    assert "Search the Marketplace" in client.get("/ha", auth=AUTH).text

    page = client.get("/marketplace", auth=AUTH).text
    assert page.index("Clock_Card") < page.index("Weather") < page.index("Forecast")  # stars
    page = client.get("/marketplace", params={"q": "WEATHER"}, auth=AUTH).text
    assert "a/weather" in page and "c/forecast-card" in page and "b/clock" not in page
    assert "Forecasts &lt;b&gt;now&lt;/b&gt;" in page and "2 matches" in page
    page = client.get("/marketplace", params={"q": "weather", "kind": "card"}, auth=AUTH).text
    assert "c/forecast-card" in page and "a/weather" not in page
    # LIKE wildcards are only text.
    page = client.get("/marketplace", params={"q": "100%"}, auth=AUTH).text
    assert "b/clock" in page and "1 match." in page
    page = client.get("/marketplace", params={"q": "_"}, auth=AUTH).text  # only Clock_Card
    assert "b/clock" in page and "1 match." in page

    r = client.post("/marketplace/scan", auth=AUTH, data={"repo": "a/weather"})
    assert r.status_code == 303
    with db.SessionLocal() as s:
        t = s.scalar(select(Target).where(Target.source == "a/weather"))
        assert (t.profile, t.origin, t.hacs_kind, t.interval_hours) == ("ha", "manual",
                                                                         "integration", 0)
        assert [(x.ref, x.status) for x in t.scans] == [("v2.0", "queued")]
    assert r.headers["location"] == f"/targets/{t.id}"
    # Again while it waits: no second scan. The page says it is on its way.
    client.post("/marketplace/scan", auth=AUTH, data={"repo": "a/weather"})
    with db.SessionLocal() as s:
        assert len(s.scalars(select(Scan)).all()) == 1
    assert "scan waiting or running" in client.get("/marketplace", params={"q": "weather"},
                                                    auth=AUTH).text  # fmt: skip

    for repo in ("not/listed", "https://evil.example/x.git"):
        assert client.post("/marketplace/scan", auth=AUTH, data={"repo": repo}).status_code == 404
    r = client.post("/marketplace/scan", auth=AUTH, data={"repo": "b/clock"},
                    headers={"Sec-Fetch-Site": "cross-site"})  # fmt: skip
    assert r.status_code == 403


def test_notifier_status_and_test_button(client):
    from scentry.models import NotifyState, utcnow

    assert "Send a test" not in client.get("/system", auth=AUTH).text  # no notify service
    with db.SessionLocal() as s:
        s.add(NotifyState(id=1, services=0, invalid_urls=1))
        s.commit()
    page = client.get("/system", auth=AUTH).text
    assert "set SCENTRY_NOTIFY_URLS" in page and "Send a test" not in page
    assert "1 notification URL\n" in page and "is ignored" in page
    with db.SessionLocal() as s:
        state = s.get(NotifyState, 1)
        state.services, state.invalid_urls, state.seen_at = 2, 0, utcnow()
        state.error, state.error_at = "Discord: <b>bad</b>", utcnow()
        s.commit()
    page = client.get("/system", auth=AUTH).text
    assert "2 services" in page and "a send failed" in page and "&lt;b&gt;bad" in page
    assert "not running" not in page
    assert "alert-dot" in page  # the System tab is flagged on every page
    assert client.post("/notify/test", auth=AUTH).status_code == 303
    assert "Test requested" in client.get("/system", auth=AUTH).text


def test_notification_settings_per_target(client):
    from scentry.models import NotifyState

    client.post("/targets", auth=AUTH, data={"profile": "ha", "source": "a/b"})
    with db.SessionLocal() as s:
        s.add(NotifyState(id=1, services=1, defaults={"score_below": 70, "min_severity": "high",
                                                      "clean_updates": False, "failures": True}))
        s.commit()
    page = client.get("/targets/1", auth=AUTH).text
    assert "blank: the default (70)" in page and "default (on)" in page
    assert "Notifications:" not in page  # nothing set yet

    form = {"score_below": "85", "failures": "off", "clean_updates": "", "min_severity": ""}
    assert client.post("/targets/1/notify", auth=AUTH, data=form).status_code == 303
    with db.SessionLocal() as s:
        t = s.get(Target, 1)
        assert (t.notify_muted, t.notify_score_below, t.notify_failures,
                t.notify_clean_updates) == (False, 85, False, None)  # fmt: skip
    assert "Notifications: its own settings" in client.get("/targets/1", auth=AUTH).text

    client.post("/targets/1/notify", auth=AUTH, data={"muted": "on"})  # the rest back to default
    with db.SessionLocal() as s:
        t = s.get(Target, 1)
        assert (t.notify_muted, t.notify_score_below, t.notify_failures) == (True, None, None)
    assert "Notifications: muted" in client.get("/targets/1", auth=AUTH).text

    for bad in ({"score_below": "0"}, {"score_below": "abc"}, {"min_severity": "info"}):
        assert client.post("/targets/1/notify", auth=AUTH, data=bad).status_code == 400
    r = client.post("/targets/1/notify", auth=AUTH, data={"muted": "on"},
                    headers={"Sec-Fetch-Site": "cross-site"})  # fmt: skip
    assert r.status_code == 403


def _owned_with_findings():
    from scentry.models import utcnow

    with db.SessionLocal() as s:
        t = Target(name="pickl", profile="owned", source="https://github.com/me/pickl.git")
        s.add(t)
        s.flush()
        s.add(Scan(target_id=t.id, status="done", score=69, verdict="D", complete=True,
                   commit_sha="abc123", finished_at=utcnow()))  # fmt: skip
        s.add_all([
            Finding(target_id=t.id, fingerprint="f1", scanner="semgrep", rule_id="eval",
                    title="eval of input", severity="critical", file="app.py", line=4,
                    message="=HYPERLINK(\"http://evil\")", evidence="eval(x)"),
            Finding(target_id=t.id, fingerprint="f2", scanner="gitleaks", rule_id="key",
                    title="key", severity="high", status="suppressed",
                    suppression_reason="false_positive", suppression_note="test key"),
            Finding(target_id=t.id, fingerprint="f3", scanner="bandit", rule_id="old",
                    title="gone", severity="low", status="fixed"),
        ])  # fmt: skip
        s.commit()
        return t.id


def test_live_refresh_only_while_scanning(client):
    from scentry.models import utcnow

    client.post("/targets", auth=AUTH, data={"profile": "ha", "source": "a/b"})
    page = client.get("/targets/1", auth=AUTH).text
    assert 'http-equiv="refresh"' in page and "starting" in page
    paused = client.get("/targets/1?status=open&refresh=0", auth=AUTH).text
    assert 'http-equiv="refresh"' not in paused and "Auto-refresh paused" in paused
    with db.SessionLocal() as s:
        scan = s.get(Scan, 1)
        scan.status, scan.started_at = "running", utcnow()
        s.commit()
    assert "running for" in client.get("/scans/1", auth=AUTH).text
    with db.SessionLocal() as s:
        s.get(Scan, 1).status = "done"
        s.commit()
    page = client.get("/targets/1", auth=AUTH).text
    assert 'http-equiv="refresh"' not in page and "in progress" not in page


def test_exports(client):
    import csv
    import io
    import json

    tid = _owned_with_findings()
    r = client.get(f"/targets/{tid}/export.json", auth=AUTH)
    assert r.headers["content-disposition"].startswith('attachment; filename="scentry-pickl-')
    data = json.loads(r.text)
    assert data["format"] == 1 and data["target"]["result"]["verdict"] == "D"
    assert [f["status"] for f in data["target"]["findings"]] == ["open", "suppressed", "fixed"]
    assert data["target"]["findings"][1]["suppression"]["note"] == "test key"

    sarif = json.loads(client.get(f"/targets/{tid}/export.sarif", auth=AUTH).text)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and len(run["results"]) == 2  # fixed left out
    crit, sup = run["results"]
    assert crit["level"] == "error" and crit["ruleId"] == "semgrep/eval"
    loc = crit["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app.py" and loc["region"]["startLine"] == 4
    assert sup["suppressions"][0]["status"] == "accepted" and "locations" not in sup
    assert run["versionControlProvenance"][0]["revisionId"] == "abc123"

    everything = json.loads(client.get("/export.json", auth=AUTH).text)
    assert [t["name"] for t in everything["targets"]] == ["pickl"]

    rows = list(csv.DictReader(io.StringIO(client.get("/export/findings.csv", auth=AUTH).text)))
    assert len(rows) == 3 and rows[0]["message"].startswith("'=")  # no formula runs
    only_open = client.get("/export/findings.csv?status=open", auth=AUTH).text
    assert only_open.count("\n") == 2
    assert client.get("/export.json").status_code == 401


def test_grade_breakdown(client):
    import json

    tid = _owned_with_findings()
    page = " ".join(client.get(f"/targets/{tid}", auth=AUTH).text.split())
    assert "100 − 25 = 75, capped at 69 (an open critical: D at best)" in page
    data = json.loads(client.get(f"/targets/{tid}/export.json", auth=AUTH).text)
    assert [(i["rule_id"], i["deduction"]) for i in data["target"]["grade_issues"]] == [
        ("eval", 25)]  # fmt: skip


def test_repositories_are_mine_or_others_under_nested_tabs(client):
    def add(**data):
        r = client.post("/targets", auth=AUTH, data=data)
        return int(r.headers["location"].rsplit("/", 1)[1])

    mine = add(profile="owned", source="https://github.com/me/app.git", mine="1")
    theirs = add(profile="owned", source="https://github.com/someone/tool.git")
    card = add(profile="ha", source="owner/card")
    page = client.get("/code", auth=AUTH).text
    # The tab bar: each tab counts what its lists hold, and opens the first of them.
    assert '<a href="/code" class="tab on" aria-current="true">' in page
    assert '<span>Repositories</span><span class="badge">2</span>' in page
    assert '<span>Home Assistant</span><span class="badge">1</span>' in page
    mine_tab = '<a href="/code" class="on" aria-current="page">Mine <span class="badge">1</span>'
    assert mine_tab in page
    assert '<a href="/repos">Others <span class="badge">1</span></a>' in page
    assert "<h1>My code</h1>" in page and "me/app" in page and "someone/tool" not in page
    page = client.get("/repos", auth=AUTH).text
    assert "<h1>Other repositories</h1>" in page and "someone/tool" in page
    assert "me/app" not in page
    page = client.get("/marketplace", auth=AUTH).text
    assert '<a href="/marketplace" class="on" aria-current="page">Marketplace</a>' in page
    assert '<a href="/others">Not installed <span class="badge">1</span></a>' in page
    assert '<a href="/repos"' not in page  # only its own tab's lists
    assert 'href="/repos"' in client.get("/", auth=AUTH).text  # a card on the Overview

    # A repository's page says whose it is, and moves it.
    page = client.get(f"/targets/{theirs}", auth=AUTH).text
    assert ('<nav class="crumbs"><a href="/code">Repositories</a><span class="sep">›</span>'
            '<a href="/repos">Others</a><span class="sep">›</span>') in page  # fmt: skip
    assert "Someone else&#39;s repository" in page and "Move to Mine" in page
    r = client.post(f"/targets/{theirs}/mine", auth=AUTH, data={"on": "on"})
    assert r.headers["location"] == f"/targets/{theirs}"
    assert "someone/tool" in client.get("/code", auth=AUTH).text
    assert "Move to Others" in client.get(f"/targets/{theirs}", auth=AUTH).text
    assert client.post(f"/targets/{mine}/mine", auth=AUTH, data={"on": "x"}).status_code == 400
    # A Home Assistant target isn't anyone's code.
    assert client.post(f"/targets/{card}/mine", auth=AUTH, data={"on": "on"}).status_code == 400
    page = client.get(f"/targets/{card}", auth=AUTH).text
    assert "Move to" not in page and '<a href="/others">Not installed</a>' in page
