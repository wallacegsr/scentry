"""Barkley (https://github.com/SeriesOfTubez/ha-barkley, MIT), the Home Assistant
engine, driven through its `sniff-test` command line and JSON report.

Two modes:
- profile "ha": Barkley fetches owner/repo itself, at the version the Marketplace
  would install, and its score and verdict are the scan's result.
- profile "owned": Barkley reads the cloned tree of a repository that contains a
  Home Assistant integration or card, and its findings join the others.
"""

from __future__ import annotations

import datetime
import json
import re

from scentry import proc, sarif
from scentry.models import SEVERITY_RANK, utcnow
from scentry.scanners.base import RawFinding, ScanContext, Scanner, ScannerRun

SUPPORTED_SCHEMA = 1
_DROP = ("context", "ai_brief")  # bulky, and only useful to Barkley's own panel


_LIMITED = re.compile(r"API limit is used up|rate limit exceeded", re.IGNORECASE)
_RESETS = re.compile(r"resets at (\d{1,2}):(\d{2}) UTC")


def rate_limit_reset(output: str, now: datetime.datetime) -> datetime.datetime | None:
    """When Barkley stopped because GitHub's API limit is used up: when to try again
    (the reset time it names, plus a minute; 15 minutes if it names none)."""
    if not _LIMITED.search(output):
        return None
    m = _RESETS.search(output)
    if m is None:
        return now + datetime.timedelta(minutes=15)
    at = now.replace(hour=int(m[1]) % 24, minute=int(m[2]) % 60, second=0, microsecond=0)
    if at <= now:
        at += datetime.timedelta(days=1)
    return at + datetime.timedelta(minutes=1)


def is_ha_repo(tree) -> bool:
    if (tree / "hacs.json").is_file():
        return True
    return next(tree.glob("custom_components/*/manifest.json"), None) is not None


class Barkley(Scanner):
    name = "barkley"
    executable = "sniff-test"

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.profile == "ha" or (ctx.tree is not None and is_ha_repo(ctx.tree))

    def run(self, ctx: ScanContext) -> ScannerRun:
        out = ctx.out_dir / "barkley.json"
        env = {}
        if ctx.profile == "ha":
            cmd = ["sniff-test", "scan", ctx.source]
            if ctx.ref:
                cmd += ["--ref", ctx.ref]
            if ctx.settings.public_github_token:
                env["GITHUB_TOKEN"] = ctx.settings.public_github_token
        else:
            cmd = ["sniff-test", "scan", str(ctx.tree)]
        cmd += ["--json", "-o", str(out)]
        res = proc.run(cmd, timeout=ctx.settings.scanner_timeout, env=env)
        try:
            report = json.loads(out.read_text("utf-8"))
        except (OSError, ValueError):
            output = f"{res.stderr or ''}\n{res.stdout or ''}"
            if until := rate_limit_reset(output, utcnow()):
                return ScannerRun(self.name, "error",
                                  f"GitHub's API limit is used up until {until:%H:%M} UTC",
                                  extra={"retry_at": until})  # fmt: skip
            tail = (res.stderr or res.stdout).strip()[-400:]
            return ScannerRun(self.name, "error", f"no report (exit {res.returncode}): {tail}")
        if report.get("schema_version") != SUPPORTED_SCHEMA:
            return ScannerRun(
                self.name, "error", f"unsupported report schema {report.get('schema_version')!r}"
            )
        return ScannerRun(
            self.name,
            "ok",
            detail=f"sniff-test {(report.get('tool') or {}).get('version', '?')}",
            findings=[_finding(f) for f in report.get("findings") or []],
            extra={
                "score": report.get("score"),
                "verdict": (report.get("verdict") or {}).get("label"),
                "complete": bool(report.get("complete")),
                "commit_sha": (report.get("target") or {}).get("commit_sha"),
                "ref": (report.get("target") or {}).get("ref"),
                "report": {k: v for k, v in report.items() if k not in _DROP},
            },
        )


def _finding(f: dict) -> RawFinding:
    severity = str(f.get("severity") or "medium").lower()
    line = f.get("line")
    return RawFinding(
        scanner="barkley",
        rule_id=sarif.clean(f.get("rule_id") or "unknown", 300),
        title=sarif.clean(f.get("title") or f.get("rule_id"), 300),
        severity=severity if severity in SEVERITY_RANK else "medium",
        message=sarif.clean(f.get("message"), 2000),
        category=sarif.clean(f.get("category"), 50),
        file=sarif.clean(f.get("file"), 1000) or None,
        line=line if isinstance(line, int) else None,
        evidence=sarif.clean(f.get("evidence"), 500) or None,
    )
