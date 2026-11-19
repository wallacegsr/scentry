"""Suppressing several findings at once, and the findings table's Last seen column."""

from __future__ import annotations

import datetime
import re

import pytest
from fastapi.testclient import TestClient

from scentry import db
from scentry.config import Settings
from scentry.models import Finding, RuleSuppression, Target, utcnow
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


def test_suppress_a_rule_in_a_folder(client):
    with db.SessionLocal() as s:
        for n, rule, file in ((7, "no-csrf-token", "web/templates/a.html"),
                              (8, "no-csrf-token", "web/templates/x/b.html"),
                              (9, "no-csrf-token", "web/other.html"),
                              (10, "bind-all", "web/templates/c.html"), (11, "bind-all", None)):
            s.add(Finding(target_id=1, fingerprint=f"f{n}", scanner="semgrep", rule_id=rule,
                          title=f"{rule} {n}", severity="medium", file=file))  # fmt: skip
        s.commit()
    assert 'href="/findings/7/suppress-rule">suppress this rule in a folder</a>' in client.get(
        "/findings/7", auth=AUTH).text  # fmt: skip
    assert "suppress-rule" not in client.get("/findings/11", auth=AUTH).text  # no file
    assert client.get("/findings/11/suppress-rule", auth=AUTH).status_code == 400

    # It starts from the finding's folder, and shows what a pattern takes in before saving.
    page = client.get("/findings/7/suppress-rule", auth=AUTH).text
    assert 'name="pattern" value="web/templates/" class="mono" required>' in page
    assert "2 findings" in page and "no-csrf-token 8" in page
    assert "no-csrf-token 9" not in page and "bind-all 10" not in page
    assert '<input type="hidden" name="pattern" value="web/templates/">' in page
    assert "3 findings" in client.get("/findings/7/suppress-rule", params={"pattern": "web/"},
                                      auth=AUTH).text  # fmt: skip
    for pattern, says in (("**", "can&#39;t be suppressed in every file"),
                          ("tests/", "this finding&#39;s own file, web/templates/a.html")):
        page = client.get("/findings/7/suppress-rule", params={"pattern": pattern}, auth=AUTH).text
        assert says in page and 'method="post"' not in page

    form = {"pattern": "web/templates/", "reason": "false_positive", "note": "Jinja, not Django",
            "days": "0"}  # fmt: skip
    for change, says in (({"pattern": "**"}, "every file"), ({"note": " "}, "needs a note"),
                         ({"reason": "nope"}, "needs a reason")):
        r = client.post("/findings/7/suppress-rule", data={**form, **change}, auth=AUTH)
        assert r.status_code == 400 and says in r.text
    cross = client.post("/findings/7/suppress-rule", data=form, auth=AUTH,
                        headers={"Sec-Fetch-Site": "cross-site"})  # fmt: skip
    assert cross.status_code == 403 and _findings()[7].status == "open"

    ok = client.post("/findings/7/suppress-rule", data=form, auth=AUTH)
    assert ok.status_code == 303 and ok.headers["location"] == "/targets/1#rules"
    found = _findings()
    for i in (7, 8):
        assert (found[i].status, found[i].rule_suppression_id, found[i].suppressed_until,
                found[i].suppression_note) == ("suppressed", 1, None, "Jinja, not Django")
    assert [found[i].status for i in (1, 9, 10)] == ["open"] * 3
    again = client.post("/findings/9/suppress-rule", data={**form, "pattern": "web/"}, auth=AUTH)
    assert again.status_code == 303  # a wider one is another suppression
    assert _findings()[9].rule_suppression_id == 2
    same = client.post("/findings/9/suppress-rule", data={**form, "pattern": "web/"}, auth=AUTH)
    assert same.status_code == 400 and "already suppressed in files matching web/" in same.text

    # The target lists them, its suppressed findings and each finding say which covers them.
    page = client.get("/targets/1", auth=AUTH).text
    assert '<section class="card" id="rules">' in page and "Jinja, not Django" in page
    assert 'href="?status=suppressed&amp;q=no-csrf-token#findings">2</a>' in page
    assert ('the rule, in <span class="mono">web/templates/</span>'
            in client.get("/targets/1?status=suppressed", auth=AUTH).text)  # fmt: skip
    assert "for this rule in files matching <code>web/templates/</code>" in client.get(
        "/findings/8", auth=AUTH).text  # fmt: skip
    export = client.get("/targets/1/export.json", auth=AUTH).json()["target"]
    assert [(r["pattern"], r["active"], r["until"]) for r in export["rule_suppressions"]] == [
        ("web/templates/", True, None), ("web/", True, None)]
    by_id = {f["id"]: f for f in export["findings"]}
    assert by_id[8]["suppression"]["rule_suppression"] == 1

    # Reopened by hand, a finding is on its own again. Removing a suppression reopens what
    # it still covers, unless another one takes it in.
    client.post("/findings/8/reopen", auth=AUTH)
    assert _findings()[8].rule_suppression_id is None
    assert client.post("/rule-suppressions/99/remove", auth=AUTH).status_code == 404
    r = client.post("/rule-suppressions/1/remove", auth=AUTH)
    assert r.status_code == 303 and r.headers["location"] == "/targets/1#rules"
    found = _findings()
    assert (found[7].status, found[7].rule_suppression_id) == ("suppressed", 2)  # web/
    assert (found[8].status, found[9].rule_suppression_id) == ("open", 2)
    client.post("/rule-suppressions/2/remove", auth=AUTH)
    found = _findings()
    assert [(found[i].status, found[i].rule_suppression_id) for i in (7, 9)] == [("open", None)] * 2
    assert 'id="rules"' not in client.get("/targets/1", auth=AUTH).text

    # Removing the target removes its rule suppressions.
    client.post("/findings/7/suppress-rule", data=form, auth=AUTH)
    client.post("/targets/1/delete", auth=AUTH)
    with db.SessionLocal() as s:
        assert s.query(Target).count() == 1 and s.query(RuleSuppression).count() == 0
