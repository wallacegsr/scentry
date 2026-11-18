"""Sharing a finding: Markdown for a GitHub issue, an advisory or a message."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from scentry import ai, db, export
from scentry.config import Settings
from scentry.models import Finding, Scan, Target, utcnow
from scentry.web.app import create_app

AUTH = ("admin", "pw")
WJ = export.WORD_JOINER


@pytest.fixture
def client(tmp_path):
    settings = Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'web.db'}",
                        admin_password="pw")  # fmt: skip
    return TestClient(create_app(settings), follow_redirects=False)


def add(profile="owned", source="https://github.com/me/app.git", explained=False, **finding):
    """A target with one scan and one finding; returns the finding's id."""
    with db.SessionLocal() as s:
        t = Target(name="app", profile=profile, source=source)
        s.add(t)
        s.flush()
        scan = Scan(target_id=t.id, status="done", ref="v1.2", commit_sha="abc123def4567890",
                    complete=True, finished_at=utcnow())  # fmt: skip
        s.add(scan)
        s.flush()
        fields = {"scanner": "semgrep", "rule_id": "eval-detected", "title": "eval on input",
                  "severity": "high", "file": "app/calc.py", "line": 22,
                  "message": "Detected eval(). Ask @alice, see #12.",
                  "evidence": "result = eval(request.json['expr'])"} | finding  # fmt: skip
        f = Finding(target_id=t.id, fingerprint="f", last_seen_scan_id=scan.id, **fields)
        s.add(f)
        s.commit()
        if explained:
            note = ai.request(s, "finding", f.id, t.id, "admin")
            note.status, note.model = "done", "qwen3.5:9b"
            note.result = {"summary": "Runs code from the request @bob.", "real": "likely",
                           "reason": "eval of request data.", "fix": "Use a parser."}  # fmt: skip
            s.commit()
        return f.id


def test_untrusted_text_stays_text():
    text = export.md_text("Hi @alice, see #12 and other/repo#3\n<img src=x> [a](b) *b* `c`\n"
                          "- item\n1. one\n# head\n===\n    indented")  # fmt: skip
    assert f"@{WJ}alice" in text and f"#{WJ}12" in text and f"repo#{WJ}3" in text
    assert "\\<img src=x\\>" in text and "\\[a\\](b)" in text and "\\*b\\*" in text
    assert "\\`c\\`" in text
    assert text.splitlines()[2:] == ["\\- item", "1\\. one", "\\# head", "\\===", "indented"]
    assert export.md_code("a `b` c") == "``a `b` c``"
    assert export.md_code("`x") == "`` `x ``"
    # A fence inside the excerpt can't close the block around it.
    assert export.md_block("x\n```\ny", "python") == "````python\nx\n```\ny\n````"


def test_github_repo_and_links(client):
    def repo(profile, source):
        return export.github_repo(Target(name="t", profile=profile, source=source))

    assert repo("owned", "https://github.com/me/app.git") == "me/app"
    assert repo("owned", "https://github.com/me/app") == "me/app"
    assert repo("owned", "https://gitlab.com/me/app.git") is None
    assert repo("owned", "/srv/code/app") is None
    assert repo("ha", "someone/ha-thing") == "someone/ha-thing"

    fid = add()
    with db.SessionLocal() as s:
        f = s.get(Finding, fid)
        scan = s.get(Scan, f.last_seen_scan_id)
        assert export.source_link("me/app", scan, f) == (
            "https://github.com/me/app/blob/abc123def4567890/app/calc.py#L22")
        f.file = "../etc/passwd"
        assert export.source_link("me/app", scan, f) is None
    url, whole = export.new_issue_url("me/app", "eval on input", "body text")
    assert whole and url == ("https://github.com/me/app/issues/new?"
                             "title=eval+on+input&body=body+text")
    url, whole = export.new_issue_url("me/app", "t", "x" * 9000)
    assert not whole and "body=" not in url


def test_finding_markdown(client):
    fid = add(explained=True, evidence="ok = 1\n```\n@carol", vulns={
        "package": "aiohttp", "groups": [["GHSA-abcd-efgh-ijkl", "CVE-2026-12345"]]})
    with db.SessionLocal() as s:
        f = s.get(Finding, fid)
        scan = s.get(Scan, f.last_seen_scan_id)
        plain = export.finding_markdown(f, scan)
        explained = export.finding_markdown(f, scan, ai.note_for(s, "finding", fid))
    assert plain.startswith("### eval on input\n\n- **Severity:** high\n")
    assert "rule `eval-detected`" in plain
    assert ("[`app/calc.py:22`](https://github.com/me/app/blob/abc123def4567890/"
            "app/calc.py#L22)") in plain
    assert "**Version scanned:** `v1.2` (commit `abc123def456`)" in plain
    assert ("`aiohttp`: [GHSA-abcd-efgh-ijkl](https://github.com/advisories/GHSA-abcd-efgh-ijkl)"
            " = [CVE-2026-12345](https://www.cve.org/CVERecord?id=CVE-2026-12345)") in plain
    assert f"Ask @{WJ}alice, see #{WJ}12." in plain
    assert "````python\nok = 1\n```\n@carol\n````" in plain  # in code: no mention
    assert "Explanation" not in plain
    assert "#### Explanation by `qwen3.5:9b`" in explained and "It can be wrong." in explained
    assert f"Runs code from the request @{WJ}bob." in explained
    assert "**Looks real:** eval of request data." in explained
    assert "**What to do:** Use a parser." in explained


def test_add_on_reports_leave_out_install_advice_and_secrets(client):
    fid = add(profile="ha", source="someone/ha-thing", explained=True)
    secret = add(scanner="gitleaks", rule_id="generic-api-key", evidence="REDACTED")
    with db.SessionLocal() as s:
        f = s.get(Finding, fid)
        text = export.finding_markdown(f, s.get(Scan, f.last_seen_scan_id),
                                       ai.note_for(s, "finding", fid))  # fmt: skip
        assert "**Looks real:**" in text and "What to do" not in text
        assert "github.com/someone/ha-thing/blob/" in text
        leak = s.get(Finding, secret)
        assert "REDACTED" not in export.finding_markdown(leak, None)


def test_share_page(client):
    fid = add(evidence="<img src=x onerror=alert(1)>")
    assert client.get(f"/findings/{fid}/share").status_code == 401
    assert client.get("/findings/999/share", auth=AUTH).status_code == 404
    assert f'href="/findings/{fid}/share"' in client.get(f"/findings/{fid}", auth=AUTH).text

    page = client.get(f"/findings/{fid}/share", auth=AUTH).text
    assert "<img src" not in page and "&lt;img src=x onerror=alert(1)&gt;" in page
    issue = "https://github.com/me/app/issues/new?title=eval+on+input+in+app%2Fcalc.py&amp;body="
    assert f'href="{issue}' in page
    assert "https://github.com/me/app/security/advisories/new" in page
    assert "opens filled in" in page and "Without explanation" not in page  # nothing to add

    md = client.get(f"/findings/{fid}/finding.md", auth=AUTH)
    assert md.headers["content-type"].startswith("text/markdown")
    disposition = md.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="scentry-app-finding-')
    assert md.text.startswith("### eval on input")


def test_share_with_or_without_the_explanation(client):
    fid = add(explained=True)
    without = client.get(f"/findings/{fid}/share", auth=AUTH).text
    assert "Without explanation" in without and "With qwen3.5:9b's explanation" in without
    assert "Explanation by" not in without
    assert f'href="/findings/{fid}/finding.md?explain=0"' in without
    shown = client.get(f"/findings/{fid}/share?explain=1", auth=AUTH).text
    assert "Explanation by" in shown and f'href="/findings/{fid}/finding.md?explain=1"' in shown
    assert "Explanation by" in client.get(f"/findings/{fid}/finding.md?explain=1", auth=AUTH).text


def test_share_add_on_and_elsewhere(client):
    ha = client.get(f"/findings/{add(profile='ha', source='someone/ha-thing')}/share",
                    auth=AUTH).text  # fmt: skip
    assert "someone else's code" in ha
    assert 'href="https://github.com/someone/ha-thing/security"' in ha
    elsewhere = client.get(f"/findings/{add(source='https://gitlab.com/me/app.git')}/share",
                           auth=AUTH).text  # fmt: skip
    assert "isn't on GitHub" in elsewhere and "issues/new" not in elsewhere
    long = client.get(f"/findings/{add(evidence='x = 1\n' * 2000)}/share", auth=AUTH).text
    assert "too long to fill in" in long and "&amp;body=" not in long
