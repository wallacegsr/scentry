"""The benchmark's labelling sheet: made from a target's export, filled in by hand."""

from __future__ import annotations

import csv
import json

import pytest

from scentry import bench


def finding(id, scanner, rule_id, severity, file, line, **kw):
    return {"id": id, "fingerprint": f"{id:064x}", "scanner": scanner, "rule_id": rule_id,
            "severity": severity, "title": rule_id, "message": "", "file": file, "line": line,
            "evidence": None, "same_as": None, "status": "open", **kw}  # fmt: skip


def export(*found):
    return {"tool": "scentry", "format": 1, "target": {"name": "app", "findings": list(found)}}


SQLI = "go.lang.security.audit.sqli.gosql-sqli.gosql-sqli"
FORMATTED = "go.lang.security.audit.database.string-formatted-query.string-formatted-query"


@pytest.mark.parametrize(("path", "place"), [
    ("app/backend/internal/api/arr_keep_test.go", "test"),
    ("app/frontend/src/lib/migrate/folder-paths.test.ts", "test"),
    ("internal/fakesite/server.go", "test"),
    ("pkg/testdata/key.pem", "test"),
    ("tests/test_x.py", "test"),
    (".github/workflows/ci.yml", "ci"),
    ("app/frontend/package-lock.json", "dependencies"),
    ("go.sum", "dependencies"),
    ("docs/setup.md", "docs"),
    ("README.md", "docs"),
    ("deploy/Dockerfile", "build"),
    ("Dockerfile.dev", "build"),
    ("app/backend/tools/demo/inspect.go", "build"),
    ("scripts/release.sh", "build"),
    ("app/backend/internal/downloads/grab.go", "code"),
    ("contest/main.go", "code"),  # not a test folder
    (None, ""),
])  # fmt: skip
def test_where_a_file_is(path, place):
    assert bench.where(path) == place


def test_the_sheet_groups_rules_and_gives_hints():
    rows = bench.sheet_rows(export(
        finding(3, "semgrep", FORMATTED, "medium", "grab.go", 653),
        finding(1, "semgrep", SQLI, "high", "grab.go", 653),
        finding(2, "semgrep", SQLI, "high", "inspect.go", 36),
        finding(4, "osv-scanner", "CVE-2026-1", "medium", "go.mod", None),
        finding(5, "barkley", "GHSA-xxxx", "low", "go.mod", None, same_as=4),
        finding(6, "gitleaks", "generic-api-key", "high", "a_test.go", 9,
                evidence="=HYPERLINK(\"http://x\")", status="suppressed"),
        finding(7, "semgrep", SQLI, "high", "old.go", 1, status="fixed"),  # not labelled
    ))  # fmt: skip
    assert [r["finding"] for r in rows] == ["6", "1", "2", "4", "3", "5"]  # worst rules first
    first = rows[1]
    assert first["key"] == "fp-" + f"{1:064x}"[:16] and first["label"] == first["notes"] == ""
    assert (first["rule"], first["rule_id"], first["where"]) == ("gosql-sqli", SQLI, "code")
    assert first["hints"] == ("an audit rule (Semgrep: look closer, often not a problem); "
                              "2 findings of this rule; also here: semgrep: "
                              "string-formatted-query")  # fmt: skip
    assert rows[2]["hints"].endswith("2 findings of this rule")  # nothing else on its line
    assert "also here: semgrep: gosql-sqli" in rows[4]["hints"]
    assert rows[5]["hints"] == ("the same vulnerability as finding 4 (CVE-2026-1): "
                                "not counted on its own")  # fmt: skip
    secret = rows[0]
    assert secret["evidence"] == "'=HYPERLINK(\"http://x\")"  # a spreadsheet won't run it
    assert (secret["where"], secret["status"], secret["line"]) == ("test", "suppressed", "9")


def test_a_sheet_round_trips_through_a_spreadsheet(tmp_path):
    sheet = tmp_path / "labels.csv"
    found = [finding(i, "semgrep", f"r{i % 3}", "high", "a.go", i) for i in range(1, 7)]
    assert bench.write_sheet(export(*found), sheet) == 6
    assert sheet.read_bytes().startswith(b"\xef\xbb\xbf")  # Excel reads it as UTF-8
    rows = bench.read_sheet(sheet)
    labels = ["tp", " FP ", "needs context", "maybe", "", "Context"]
    for row, label in zip(rows, labels, strict=True):
        row["label"] = label
    # Saved again by Excel set to a region that separates with semicolons, in its code page.
    with (tmp_path / "saved.csv").open("w", encoding="cp1252", newline="") as fh:
        writer = csv.DictWriter(fh, bench.COLUMNS, delimiter=";")
        writer.writeheader()
        writer.writerows(rows)
    report = bench.status(tmp_path / "saved.csv")
    assert "4 of 6 labelled." in report
    assert next(r for r in report.splitlines() if r.startswith("all ")).split() == [
        "all", "1", "1", "2", "1", "1"]  # tp fp context ? unlabelled
    assert f"Not a label (use tp, fp, context): {rows[3]['key']}: 'maybe'" in report


def test_status_refuses_something_else(tmp_path):
    other = tmp_path / "findings.csv"
    other.write_text("target,rule_id\napp,x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no key column"):
        bench.status(other)


def test_the_commands(tmp_path, capsys):
    exported = tmp_path / "export.json"
    exported.write_text(json.dumps(export(finding(1, "semgrep", SQLI, "high", "a.go", 1))))
    bench.main(["sheet", str(exported), str(tmp_path / "s.csv")])
    assert "1 findings in" in capsys.readouterr().out
    bench.main(["status", str(tmp_path / "s.csv")])
    assert "0 of 1 labelled." in capsys.readouterr().out
