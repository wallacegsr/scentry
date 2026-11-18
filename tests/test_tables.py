"""Tables sort and search on the server (the portal runs no JavaScript), and the tabs."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import QueryParams

from scentry import db
from scentry.config import Settings
from scentry.models import Finding, Scan, Target, utcnow
from scentry.web.app import create_app
from scentry.web.tables import view

AUTH = ("admin", "pw")
ROWS = [{"name": "beta", "score": 70}, {"name": "Alpha", "score": None},
        {"name": "gamma", "score": 95}]  # fmt: skip


def table(query: str, **kw):
    return view(QueryParams(query), ROWS, sorts={"name": lambda r: r["name"],
                                                 "score": lambda r: r["score"]},
                default="name", text=lambda r: [r["name"]], **kw)  # fmt: skip


def names(v):
    return [r["name"] for r in v.rows]


def test_sort_and_search():
    assert names(table("")) == ["Alpha", "beta", "gamma"]  # case doesn't matter
    assert names(table("sort=name&dir=desc")) == ["gamma", "beta", "Alpha"]
    # Empty values go last whichever way round.
    assert names(table("sort=score")) == ["beta", "gamma", "Alpha"]
    assert names(table("sort=score&dir=desc")) == ["gamma", "beta", "Alpha"]
    assert names(table("sort=nonsense")) == ["Alpha", "beta", "gamma"]
    v = table("q=  AL ")
    assert names(v) == ["Alpha"] and (v.q, v.total) == ("AL", 3)
    assert names(table("q=a m")) == ["gamma"]  # every word must match


def test_links_keep_the_rest_of_the_page():
    v = table("status=fixed&sort=name&q=a&other_sort=x&refresh=0", anchor="t",
              desc_first=("score",))  # fmt: skip
    href = v.href("name")  # sorted by name already: the other way round
    assert href.endswith("#t")
    query = parse_qs(urlsplit(href).query)
    assert query == {"status": ["fixed"], "other_sort": ["x"], "sort": ["name"],
                     "dir": ["desc"], "q": ["a"]}  # fmt: skip
    assert parse_qs(urlsplit(v.href("score")).query)["dir"] == ["desc"]  # high first
    assert v.aria("name") == "ascending" and v.aria("score") == "none"
    assert ("status", "fixed") in v.hidden and ("sort", "name") in v.hidden
    assert "q=" not in v.clear
    # Two tables on one page don't touch each other's parameters.
    other = view(QueryParams("sort=name&scans_sort=id&scans_dir=desc"), [], prefix="scans_",
                 sorts={"id": lambda s: s}, default="id", text=lambda s: [])  # fmt: skip
    assert (other.sort, other.desc) == ("id", True)
    assert parse_qs(urlsplit(other.href("id")).query)["sort"] == ["name"]


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 't.db'}",
                              admin_password="pw"))  # fmt: skip
    return TestClient(app, follow_redirects=False)


def add(session, name, profile, score, **kw):
    t = Target(name=name, profile=profile, source=f"https://git.example/{name}.git"
               if profile == "owned" else f"o/{name}", **kw)  # fmt: skip
    session.add(t)
    session.flush()
    session.add(Scan(target_id=t.id, status="done", ref="main", score=score,
                     verdict="A" if score >= 90 else "D", complete=True,
                     finished_at=utcnow()))  # fmt: skip
    session.flush()
    return t


def test_tabs_list_their_own_targets_sorted_and_searched(client):
    with db.SessionLocal() as s:
        add(s, "zeta", "owned", 95)
        add(s, "alpha", "owned", 61)
        add(s, "card", "ha", 90, hacs_kind="card")
        add(s, "installed", "ha", 92, origin="hacs", installed_version="main")
        s.commit()
    code = client.get("/code", auth=AUTH).text
    assert code.index("alpha") < code.index("zeta") and "o/card" not in code
    assert 'aria-current="page"' in code and "popovertarget=\"add-target\"" in code
    assert 'name="profile" value="owned"' in code
    by_score = client.get("/code?sort=score&dir=desc", auth=AUTH).text
    assert by_score.index("zeta") < by_score.index("alpha")
    found = client.get("/code?q=ZET", auth=AUTH).text
    assert "zeta" in found and ">alpha<" not in found and "1 of 2" in found
    others = client.get("/others", auth=AUTH).text
    assert "o/card" in others and "o/installed" not in others
    assert 'name="profile" value="ha"' in others
    assert "o/installed" in client.get("/ha", auth=AUTH).text
    # Each tab's count, on every page.
    assert '<span class="badge">2</span>' in client.get("/system", auth=AUTH).text
    # The overview: a low score is worth a look.
    overview = client.get("/", auth=AUTH).text
    assert "Needs a look" in overview and "scores 61" in overview
    assert "4 targets watched" in overview


def test_findings_lead_to_their_own_page(client):
    with db.SessionLocal() as s:
        t = add(s, "app", "owned", 70)
        s.add_all([Finding(target_id=t.id, fingerprint=str(i), scanner="semgrep", rule_id=f"r{i}",
                           title=title, severity=sev, file="a.py", line=i)
                   for i, (title, sev) in enumerate([("Low thing", "low"),
                                                     ("Bad thing", "critical")])])  # fmt: skip
        s.commit()
        tid = t.id
    def listed(query=""):  # the findings table, not the grade's above it
        page = client.get(f"/targets/{tid}{query}", auth=AUTH).text
        return page[page.index('id="findings"'):]

    page = listed()
    assert page.index("Bad thing") < page.index("Low thing")  # worst first
    page = listed("?sort=title")
    assert page.index("Bad thing") < page.index("Low thing")
    page = listed("?sort=title&dir=desc")
    assert page.index("Low thing") < page.index("Bad thing")
    page = client.get(f"/targets/{tid}", auth=AUTH).text
    assert 'href="/findings/2"' in page and 'popovertarget="remove"' in page
    finding = client.get("/findings/2", auth=AUTH).text
    assert "Bad thing" in finding and 'popovertarget="suppress"' in finding
    assert client.post("/findings/2/suppress", auth=AUTH, data={
        "reason": "false_positive", "note": "n", "days": "0"}).status_code == 303
    assert "Reopen" in client.get("/findings/2", auth=AUTH).text
    assert client.post("/findings/2/reopen", auth=AUTH).headers["location"] == "/findings/2"
    assert client.get("/findings/99", auth=AUTH).status_code == 404
    # Removing a target goes back to its tab.
    assert client.post(f"/targets/{tid}/delete", auth=AUTH).headers["location"] == "/code"
