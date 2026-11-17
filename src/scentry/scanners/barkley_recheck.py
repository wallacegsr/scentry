"""Barkley's advisory re-check of one stored scan, run by Barkley's own interpreter
(`python -I barkley_recheck.py STORE ID OUT`): its command line has no such command.

Standalone on purpose: it imports nothing from Scentry, which isn't installed in
Barkley's environment. Writes one JSON object to OUT:
  {"state": "same"}
  {"state": "changed", "barkley_id": N, "report": {...}}  (saved as a new stored scan)
  {"state": "error", "detail": "..."}
"""

from __future__ import annotations

import json
import sys


def main(argv: list[str]) -> int:
    store_path, scan_id, out = argv[0], int(argv[1]), argv[2]
    try:
        result = check(store_path, scan_id)
    except Exception as exc:  # noqa: BLE001 - every failure is reported, never a result
        result = {"state": "error", "detail": f"{type(exc).__name__}: {exc}"[:300]}
    with open(out, "w", encoding="utf-8") as fh:  # noqa: PTH123
        json.dump(result, fh)
    return 0


def check(store_path: str, scan_id: int) -> dict:
    from sniff_test import recheck  # noqa: PLC0415 - only in Barkley's environment
    from sniff_test.store import Store  # noqa: PLC0415

    store = Store(store_path)
    row = store.get(scan_id)
    if row is None:
        return {"state": "error", "detail": f"Barkley's store has no scan #{scan_id}"}
    inputs = store.inputs(scan_id)
    if inputs is None:
        return {"state": "error", "detail": "the scan kept no package list to ask about"}
    report = store.report(scan_id)
    try:
        new = recheck.recheck(report, inputs, scan_id, row.scanned_at)
    except recheck.RecheckError as exc:
        store.note_recheck(scan_id, f"error: {exc}")
        return {"state": "error", "detail": str(exc)[:300]}
    if new is None:
        store.note_recheck(scan_id, "same")
        return {"state": "same"}
    sid = store.save(new, inputs=inputs)
    store.link_source(sid, scan_id)  # the code is the old scan's
    store.note_recheck(scan_id, f"changed: #{sid}")
    return {"state": "changed", "barkley_id": sid, "report": new}


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
