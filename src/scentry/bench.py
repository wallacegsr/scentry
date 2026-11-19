"""A benchmark of findings labelled by hand: a real problem, not one, or it depends.

Before scoring changes, a scan's findings are labelled once, so that every later change can
be checked against them: no finding labelled real may lose weight, and how many labelled
not-a-problem it lets go is the measure of the change. The labels are kept outside this
repository (a scanned project's findings aren't ours to publish), in a sheet that `sheet`
makes from a target's export and you fill in; `status` says how far along it is.
"""

from __future__ import annotations

import collections
import csv
import io
import json
import re
from pathlib import Path
from typing import Any

from scentry.export import _cell
from scentry.models import SEVERITY_RANK

LABELS = {
    "tp": "a real problem: worth fixing, or a real secret",
    "fp": "not a problem: the rule matched, but the code is safe",
    "context": "can't tell from the code: it depends on how it's deployed or used",
}
_ALIASES = {"true positive": "tp", "false positive": "fp", "needs context": "context",
            "ctx": "context"}  # fmt: skip

COLUMNS = ("key", "label", "notes", "severity", "scanner", "rule", "where", "file", "line",
           "hints", "title", "message", "evidence", "status", "finding", "rule_id")  # fmt: skip

# Where in a project a file is: a hint for labelling, not a verdict. A real secret in a
# test is still a real secret. First match wins.
_PLACES = (
    ("test", re.compile(
        r"(^|/)(tests?|testdata|testing|__tests__|__mocks__|specs?|fixtures?|mocks?|fakes?|"
        r"fakesite)/|_test\.(go|py)$|(^|/)test_[^/]*\.py$|\.(test|spec)\.[cm]?[jt]sx?$",
        re.IGNORECASE)),
    ("ci", re.compile(r"(^|/)(\.github|\.circleci|\.gitlab)/|(^|/)\.gitlab-ci\.ya?ml$",
                      re.IGNORECASE)),  # fmt: skip
    ("dependencies", re.compile(
        r"(^|/)(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|go\.(mod|sum)|"
        r"requirements[^/]*\.txt|poetry\.lock|uv\.lock|Pipfile(\.lock)?|Cargo\.(toml|lock)|"
        r"Gemfile(\.lock)?|composer\.(json|lock))$", re.IGNORECASE)),
    ("docs", re.compile(r"(^|/)docs?/|\.(md|rst|adoc)$", re.IGNORECASE)),
    ("build", re.compile(
        r"(^|/)(deploy|scripts?|build|tools?|hack|docker)/|(^|/)(Dockerfile|Containerfile)"
        r"[^/]*$|(^|/)(Makefile|(docker-)?compose[^/]*\.ya?ml)$|\.(sh|ps1|bat)$",
        re.IGNORECASE)),
)


def where(path: str | None) -> str:
    """test, ci, dependencies, docs, build (build, deploy and tool scripts) or code."""
    if not path:
        return ""
    return next((name for name, pattern in _PLACES if pattern.search(path)), "code")


def _rule(scanner: str, rule_id: str) -> str:
    """Semgrep's rule ids repeat their last part (`a.b.name.name`): the name alone."""
    return rule_id.rsplit(".", 1)[-1] if scanner == "semgrep" else rule_id


def _hints(f: dict, by_rule: collections.Counter, by_line: dict, by_id: dict) -> str:
    out = []
    if f["scanner"] == "semgrep" and ".audit." in f["rule_id"]:
        out.append("an audit rule (Semgrep: look closer, often not a problem)")
    n = by_rule[(f["scanner"], f["rule_id"])]
    if n > 1:
        out.append(f"{n} findings of this rule")
    others = sorted({f"{o['scanner']}: {_rule(o['scanner'], o['rule_id'])}"
                     for o in by_line.get((f["file"], f["line"]), [])
                     if (o["scanner"], o["rule_id"]) != (f["scanner"], f["rule_id"])})  # fmt: skip
    if others:
        out.append("also here: " + ", ".join(others))
    twin = by_id.get(f.get("same_as"))
    if twin:
        out.append(f"the same vulnerability as finding {twin['id']} ({twin['rule_id']}): "
                   "not counted on its own")  # fmt: skip
    return "; ".join(out)


def sheet_rows(export: dict) -> list[dict[str, Any]]:
    """One row per finding of a target's export (not fixed ones), a rule's findings
    together, the worst rules first. Text from the scanned code is defused for a
    spreadsheet."""
    found = [f for f in export["target"]["findings"] if f.get("status") != "fixed"]
    by_rule = collections.Counter((f["scanner"], f["rule_id"]) for f in found)
    by_line: dict[tuple, list[dict]] = {}
    for f in found:
        if f.get("file") and f.get("line"):
            by_line.setdefault((f["file"], f["line"]), []).append(f)
    by_id = {f["id"]: f for f in found}
    found.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["scanner"], f["rule_id"],
                              f.get("file") or "", f.get("line") or 0))  # fmt: skip
    rows = []
    for f in found:
        row = {
            "key": key(f["fingerprint"]),
            "label": "",
            "notes": "",
            "severity": f["severity"],
            "scanner": f["scanner"],
            "rule": _rule(f["scanner"], f["rule_id"]),
            "where": where(f.get("file")),
            "file": f.get("file") or "",
            "line": f.get("line") or "",
            "hints": _hints(f, by_rule, by_line, by_id),
            "title": (f.get("title") or "")[:200],
            "message": (f.get("message") or "")[:300],
            "evidence": (f.get("evidence") or "")[:200],
            "status": f.get("status") or "",
            "finding": f["id"],
            "rule_id": f["rule_id"],
        }
        rows.append({k: _cell(v) for k, v in row.items()})
    return rows


def key(fingerprint: str) -> str:
    """A finding's key in a sheet: its fingerprint's start, which stays the same from scan
    to scan while the code doesn't change. "fp-" keeps a spreadsheet from reading it as a
    number (1234e56 would be one)."""
    return "fp-" + fingerprint[:16]


def write_sheet(export: dict, out: Path) -> int:
    rows = sheet_rows(export)
    with out.open("w", encoding="utf-8-sig", newline="") as fh:  # the BOM: Excel reads UTF-8
        writer = csv.DictWriter(fh, COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def read_sheet(path: Path) -> list[dict[str, str]]:
    """A sheet as saved again from a spreadsheet: UTF-8 or the local code page, commas or
    semicolons (Excel uses what the system's region says)."""
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1252", errors="replace")
    head = text.split("\n", 1)[0]
    delimiter = ";" if head.count(";") > head.count(",") else ","
    return list(csv.DictReader(io.StringIO(text), delimiter=delimiter))


def label_of(value: str | None) -> str | None:
    """tp, fp or context; None when blank; "?" when it's none of those."""
    text = " ".join((value or "").split()).lower()
    if not text:
        return None
    text = _ALIASES.get(text, text)
    return text if text in LABELS else "?"


def status(path: Path) -> str:
    """How much of a sheet is labelled, and with what, by scanner."""
    rows = read_sheet(path)
    if rows and "key" not in rows[0]:
        raise ValueError("That isn't a labelling sheet: it has no key column.")
    counts: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    odd = []
    for row in rows:
        label = label_of(row.get("label"))
        counts[row.get("scanner") or "?"][label or "unlabelled"] += 1
        if label == "?":
            odd.append(f"{row.get('key')}: {row.get('label')!r}")
    total = collections.Counter()
    for c in counts.values():
        total.update(c)
    order = [*LABELS, "?", "unlabelled"]

    def line(name: str, c: collections.Counter) -> str:
        return f"{name:<14}" + "".join(f"{c[k]:>12}" for k in order)

    lines = [f"{'':<14}" + "".join(f"{k:>12}" for k in order)]
    lines += [line(name, counts[name]) for name in sorted(counts)]
    lines.append(line("all", total))
    done = sum(total[k] for k in LABELS)
    lines.append(f"{done} of {len(rows)} labelled.")
    if odd:
        lines.append("Not a label (use " + ", ".join(LABELS) + "): " + "; ".join(odd[:20]))
    return "\n".join(lines)


def main(argv: list[str]) -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="scentry bench", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    make = sub.add_parser("sheet", help="make a labelling sheet (CSV) from a target's export")
    make.add_argument("export", type=Path, help="the target's export (.json)")
    make.add_argument("out", type=Path, help="the sheet to write (.csv)")
    check = sub.add_parser("status", help="how much of a labelling sheet is filled in")
    check.add_argument("sheet", type=Path)
    args = parser.parse_args(argv)
    if args.command == "sheet":
        export = json.loads(args.export.read_text(encoding="utf-8"))
        n = write_sheet(export, args.out)
        print(f"{n} findings in {args.out}. Labels: " + "; ".join(
            f"{k} = {v}" for k, v in LABELS.items()))  # fmt: skip
    else:
        print(status(args.sheet))
