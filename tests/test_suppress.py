"""Suppressing several findings at once, and the findings table's Last seen column."""

from __future__ import annotations

import datetime
import re

import pytest
from fastapi.testclient import TestClient

from scentry import db
from scentry.config import Settings
from scentry.models import Finding, Target, utcnow
from scentry.web.app import create_app

AUTH = ("admin", "pw")


@pytest.fixture
def client(tmp_path):
    settings = Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'web.db'}",
                        admin_password="pw")  # fmt: skip
    client = TestClient(create_app(settings), follow_redirects=False)
    now = utcnow()
    with db.SessionLocal() as s:
        mine, other = Target(name="mine", profile="ha", source="a/b"), Target(
            name="other", profile="ha", source="c/d")  # fmt: skip
        s.add_all([mine, other])
        s.flush()

        def add(target, n, rule, **kw):
            s.add(Finding(target_id=target.id, fingerprint=f"f{n}", scanner="semgrep",
                          rule_id=rule, title=f"{rule} {n}", severity="medium", file=f"t{n}.html",
                          first_seen_at=now - datetime.timedelta(days=10 - n),
                          last_seen_at=now - datetime.timedelta(hours=n), **kw))  # fmt: skip

        for n in (1, 2, 3):
            add(mine, n, "no-csrf-token")  # ids 1-3
        add(mine, 4, "bind-all")  # 4
        add(mine, 5, "no-csrf-token", status="suppressed", suppression_reason="wont_fix",
            suppression_note="earlier")  # 5
        add(other, 6, "no-csrf-token")  # 6: another target's
        s.commit()
    return client


def _findings():
    with db.SessionLocal() as s:
        return {f.id: f for f in s.query(Finding)}


def test_last_seen_column(client):
    page = client.get("/targets/1", auth=AUTH).text
    assert ">Last seen</a>" in page and ">First seen</a>" in page
    assert "1 hour ago" in page and "9 days ago" in page  # finding 1: last and first seen
    newest = client.get("/targets/1?sort=last&dir=desc", auth=AUTH).text
    assert newest.index("no-csrf-token 1") < newest.index("no-csrf-token 2") < newest.index(
        "bind-all 4")  # fmt: skip


def test_ticking(client):
    page = client.get("/targets/1", auth=AUTH).text
    assert '<form id="pick" method="get" action="/targets/1/suppress"' in page
    assert page.count('form="pick"') == 4 and "checked" not in page  # the 4 open ones
    assert 'href="?select=all#findings">tick all 4 shown</a>' in page

    csrf = client.get("/targets/1", params={"q": "csrf", "select": "all"}, auth=AUTH).text
    assert csrf.count('form="pick"') == 3 and csrf.count(" checked>") == 3
    assert 'href="?q=csrf#findings">untick</a>' in csrf
    sorting = re.findall(r'href="([^"]*sort=[^"]*)"', csrf)
    assert sorting and not any("select" in h for h in sorting)  # sorting unticks
    assert 'name="select"' not in csrf  # and so does searching again

    assert 'form="pick"' not in client.get("/targets/1?status=suppressed", auth=AUTH).text


def test_suppress_page_shows_only_this_targets_open_findings(client):
    page = client.get("/targets/1/suppress", params={"ids": [2, 1, 5, 6, 99]}, auth=AUTH).text
    assert "Suppress 2 findings" in page
    assert page.count('name="ids"') == 2 and page.count('name="notes"') == 2
    assert 'value="1"' in page and 'value="2"' in page and 'value="6"' not in page
    none = client.get("/targets/1/suppress", params={"ids": [5, 6]}, auth=AUTH).text
    assert "None of the findings you ticked is open." in none


def test_suppress_many_with_one_note_or_each_its_own(client):
    form = {"ids": ["1", "2", "3"], "notes": ["", "uses a token header instead", ""],
            "reason": "false_positive", "note": "", "days": "30"}  # fmt: skip
    again = client.post("/targets/1/suppress", data=form, auth=AUTH)
    assert again.status_code == 400  # two have no note: the form again, as written
    assert "2 of them have no note" in again.text
    assert 'value="uses a token header instead"' in again.text
    assert '<option value="false_positive" selected>' in again.text
    assert all(f.status != "suppressed" or f.id == 5 for f in _findings().values())

    ok = client.post("/targets/1/suppress", data={**form, "note": "Jinja, not Django"},
                     auth=AUTH)  # fmt: skip
    assert ok.status_code == 303 and ok.headers["location"] == "/targets/1#findings"
    found = _findings()
    assert [found[i].suppression_note for i in (1, 2, 3)] == [
        "Jinja, not Django", "uses a token header instead", "Jinja, not Django"]
    for i in (1, 2, 3):
        f = found[i]
        assert (f.status, f.suppression_reason, f.suppressed_by) == (
            "suppressed", "false_positive", "admin")  # fmt: skip
        assert f.suppressed_until is not None
    assert found[4].status == "open" and found[6].status == "open"


@pytest.mark.parametrize(("change", "says"), [
    ({"reason": "nope"}, "needs a reason"),
    ({"days": "-1"}, "can&#39;t be negative"),
    ({"ids": ["5", "6"], "notes": ["", ""]}, "None of these findings is open any more."),
])  # fmt: skip
def test_suppress_many_refuses(client, change, says):
    form = {"ids": ["1"], "notes": [""], "reason": "accepted_risk", "note": "n", **change}
    r = client.post("/targets/1/suppress", data=form, auth=AUTH)
    assert r.status_code == 400 and says in r.text
    assert _findings()[1].status == "open"


def test_suppress_many_needs_a_note_field_for_each(client):
    form = {"ids": ["1", "2"], "notes": ["x"], "reason": "accepted_risk", "note": "n"}
    assert client.post("/targets/1/suppress", data=form, auth=AUTH).status_code == 400
    cross = client.post("/targets/1/suppress", auth=AUTH, headers={"Sec-Fetch-Site": "cross-site"},
                        data={"ids": ["1"], "notes": [""], "reason": "accepted_risk", "note": "n"})
    assert cross.status_code == 403 and _findings()[1].status == "open"


def test_suppress_one_and_the_rest_of_its_rule(client):
    page = client.get("/findings/1", auth=AUTH).text
    assert "Also the 2 other open findings from this rule in mine" in page
    assert "other open finding" not in client.get("/findings/4", auth=AUTH).text  # none alike

    form = {"reason": "false_positive", "note": "Jinja, not Django", "days": "0"}
    assert client.post("/findings/1/suppress", data={**form, "same_rule": "1"},
                       auth=AUTH).status_code == 303  # fmt: skip
    found = _findings()
    assert all(found[i].status == "suppressed" and found[i].suppressed_until is None
               and found[i].suppression_note == "Jinja, not Django" for i in (1, 2, 3))
    assert found[5].suppression_note == "earlier"  # already suppressed: left as it was
    assert found[4].status == "open" and found[6].status == "open"


def test_suppress_one_alone(client):
    form = {"reason": "false_positive", "note": "just this one"}
    assert client.post("/findings/2/suppress", data=form, auth=AUTH).status_code == 303
    assert [f.status for f in _findings().values()][:4] == ["open", "suppressed", "open", "open"]
