"""Barkley's plain words for one of its reports, run by Barkley's own interpreter
(`python -I barkley_plain.py REPORT OUT`): what its panel says about each rule, what the
app can do inside Home Assistant, its privacy notes, and names for the data and ports in
the report's graph. The portal shows them; it has no Barkley of its own to ask.

Standalone on purpose: it imports nothing from Scentry, which isn't installed in
Barkley's environment. Reads the report alone: nothing is fetched or scanned. Writes one
JSON object to OUT, {"version": 1, ...}, or {"error": "..."}.
"""

from __future__ import annotations

import json
import sys

VERSION = 1


def main(argv: list[str]) -> int:
    report_path, out = argv[0], argv[1]
    try:
        with open(report_path, encoding="utf-8") as fh:  # noqa: PTH123
            result = plain(json.load(fh))
    except Exception as exc:  # noqa: BLE001 - every failure is reported, never words
        result = {"error": f"{type(exc).__name__}: {exc}"[:300]}
    with open(out, "w", encoding="utf-8") as fh:  # noqa: PTH123
        json.dump(result, fh)
    return 0


def plain(report: dict) -> dict:
    from sniff_test import __version__  # noqa: PLC0415 - only in Barkley's environment
    from sniff_test.analyzers.endpoints import WELL_KNOWN_PORTS  # noqa: PLC0415
    from sniff_test.report import explain, privacy  # noqa: PLC0415

    rules = {}
    for f in report.get("findings") or []:
        rule_id = f.get("rule_id") if isinstance(f, dict) else None
        if isinstance(rule_id, str) and rule_id not in rules:
            ex = explain.explain(rule_id)
            rules[rule_id] = {
                "title": ex.title, "means": ex.means, "worry": ex.worry, "chip": ex.chip,
                "links": [[label, url] for label, url in getattr(ex, "links", ())
                          if str(url).startswith("https://")],
            }  # fmt: skip
    graph = report.get("graph") or {}
    labels, ports = {}, {}
    for node in graph.get("nodes") or []:
        kind, label = node.get("kind"), str(node.get("label") or "")
        if kind in ("data", "auth"):
            labels[label] = explain.data_label(label)
        elif kind == "port" and label.isdigit() and int(label) in WELL_KNOWN_PORTS:
            ports[label] = WELL_KNOWN_PORTS[int(label)][0]
    notes = [{"kind": n.kind, "label": n.label, "title": n.title, "means": n.means,
              "unknown": n.unknown, "hosts": n.hosts[:6], "where": n.where[:4]}
             for n in privacy.notes(report)]  # fmt: skip
    return {
        "version": VERSION,
        "barkley": __version__,
        "rules": rules,
        "can_do": explain.can_do(report),
        "data_labels": labels,
        "ports": ports,
        "privacy": notes,
    }


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
