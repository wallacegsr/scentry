"""Barkley (https://github.com/SeriesOfTubez/ha-barkley, MIT), the Home Assistant
engine, driven through its `sniff-test` command line and JSON report.

Two modes:
- profile "ha": Barkley fetches owner/repo itself, at the version the Marketplace
  would install, and its score and verdict are the scan's result.
- profile "owned": Barkley reads the cloned tree of a repository that contains a
  Home Assistant integration or card, and its findings join the others.

Also from Barkley: `compare` (what a newer version changes, `sniff-test diff`) and
`recheck` (advisories asked again for a stored scan's packages).
"""

from __future__ import annotations

import datetime
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from scentry import proc, sarif
from scentry.models import SEVERITY_RANK, utcnow
from scentry.scanners.base import RawFinding, ScanContext, Scanner, ScannerRun

SUPPORTED_SCHEMA = 1
SUPPORTED_DIFF = 1
_DROP = ("context", "ai_brief")  # bulky, and only useful to Barkley's own panel
_STORED = re.compile(r"stored\s+as\s+scan\s+#(\d+)")


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
        store = ""
        if ctx.profile == "ha":
            cmd = ["sniff-test", "scan", ctx.source]
            if ctx.ref:
                cmd += ["--ref", ctx.ref]
            if ctx.settings.public_github_token:
                env["GITHUB_TOKEN"] = ctx.settings.public_github_token
            store = ctx.settings.barkley_store
        else:
            cmd = ["sniff-test", "scan", str(ctx.tree)]
        cmd += ["-o", str(out)]
        # In the store, the scan keeps the packages it resolved, for advisory re-checks.
        # (Barkley names the stored scan only when not printing JSON.)
        cmd += ["--store", store] if store else ["--json"]
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
        stored = _STORED.search(res.stderr or "") if store else None
        detail = f"sniff-test {(report.get('tool') or {}).get('version', '?')}"
        if unfinished := unfinished_checks(report):
            detail += "; didn't finish: " + "; ".join(unfinished)
        return ScannerRun(
            self.name,
            "ok",
            detail=detail,
            findings=findings_of(report),
            extra={
                "score": report.get("score"),
                "verdict": (report.get("verdict") or {}).get("label"),
                "complete": bool(report.get("complete")),
                "unfinished": unfinished,
                "commit_sha": (report.get("target") or {}).get("commit_sha"),
                "ref": (report.get("target") or {}).get("ref"),
                "report": {k: v for k, v in report.items() if k not in _DROP},
                "barkley_id": int(stored[1]) if stored else None,
            },
        )


def unfinished_checks(report: dict) -> list[str]:
    """Barkley's own checks that failed or were skipped, each with why. Barkley itself
    ran, but they leave its report (and so the scan) incomplete."""
    return [f"{sarif.clean(a.get('name'), 50)} ({sarif.clean(a.get('detail'), 300)})"
            for a in report.get("analyzers") or []
            if isinstance(a, dict) and a.get("state") in ("error", "skipped")]  # fmt: skip


def findings_of(report: dict) -> list[RawFinding]:
    return [_finding(f) for f in report.get("findings") or [] if isinstance(f, dict)]


class BarkleyError(Exception):
    pass


def compare(old: dict, new: dict, work: Path, timeout: int) -> dict:
    """Barkley's comparison of two of its reports (`sniff-test diff`): what the newer
    version changes. Offline: both reports are files, nothing is fetched or scanned."""
    paths = [work / "old.json", work / "new.json"]
    for path, report in zip(paths, (old, new), strict=True):
        path.write_text(json.dumps(report), "utf-8")
    out = work / "diff.json"
    out.unlink(missing_ok=True)  # only this run's answer counts
    res = proc.run(["sniff-test", "diff", str(paths[0]), str(paths[1]), "--offline",
                    "--json", "-o", str(out)], timeout=timeout)  # fmt: skip
    try:
        result = json.loads(out.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        tail = (res.stderr or res.stdout or "").strip()[-300:]
        raise BarkleyError(f"no comparison (exit {res.returncode}): {tail}") from exc
    if not isinstance(result, dict) or result.get("diff_version") != SUPPORTED_DIFF:
        raise BarkleyError(f"unsupported comparison version {result.get('diff_version')!r}")
    return result


@dataclass
class Recheck:
    state: str  # same | changed | error
    detail: str = ""
    report: dict | None = None  # changed: the new report
    barkley_id: int | None = None  # changed: the new report in Barkley's store


def recheck(store: str, barkley_id: int, work: Path, timeout: int) -> Recheck:
    """Ask OSV again about the packages a stored scan resolved, with Barkley's own
    re-check (its `recheck.recheck`, run by its own interpreter: the command line has no
    such command). No code is fetched and GitHub isn't asked anything. A re-check that
    couldn't ask OSV is an error, never a result."""
    python = barkley_python()
    if python is None:
        return Recheck("error", "sniff-test isn't installed")
    out = work / "recheck.json"
    out.unlink(missing_ok=True)
    script = Path(__file__).with_name("barkley_recheck.py")
    res = proc.run([python, "-I", str(script), store, str(barkley_id), str(out)],
                   cwd=work, timeout=timeout)  # fmt: skip
    try:
        result = json.loads(out.read_text("utf-8"))
    except (OSError, ValueError):
        tail = (res.stderr or res.stdout or "").strip()[-300:]
        return Recheck("error", f"no result (exit {res.returncode}): {tail}")
    state = result.get("state")
    if state == "changed":
        report = result.get("report")
        if not isinstance(report, dict) or report.get("schema_version") != SUPPORTED_SCHEMA:
            return Recheck("error", "the re-checked report isn't one this version reads")
        return Recheck("changed", report={k: v for k, v in report.items() if k not in _DROP},
                       barkley_id=result.get("barkley_id"))  # fmt: skip
    if state == "same":
        return Recheck("same")
    return Recheck("error", sarif.clean(result.get("detail") or "unknown", 300))


def barkley_python() -> str | None:
    """The interpreter of Barkley's own environment, from its command's first line."""
    exe = shutil.which("sniff-test")
    if exe is None:
        return None
    try:
        with open(exe, "rb") as fh:  # noqa: PTH123
            first = fh.readline(500).decode("utf-8", "replace")
    except OSError:
        return None
    if not first.startswith("#!"):
        return None
    python = first[2:].strip().split()[0]
    return python if Path(python).is_file() else None


def _vulns(f: dict) -> dict | None:
    """A dependency finding's advisories (one finding per package, any number of
    advisories, each with its aliases), for merging with osv-scanner's findings."""
    dep = f.get("dependency") if isinstance(f.get("dependency"), dict) else {}
    groups = []
    for a in dep.get("advisories") or []:
        if not isinstance(a, dict):
            continue
        aliases = a.get("aliases") if isinstance(a.get("aliases"), list) else []
        if found := sarif.vulns([a.get("id"), *aliases]):
            groups += found["groups"]
    if not groups:
        return None
    return {"package": sarif.clean(dep.get("package"), 200) or None, "groups": groups[:50]}


def _finding(f: dict) -> RawFinding:
    severity = str(f.get("severity") or "medium").lower()
    line = f.get("line")
    return RawFinding(
        vulns=_vulns(f),
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
