"""The scanner plugin contract. A scanner turns a source tree into RawFindings."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scentry import proc, sarif
from scentry.config import Settings


@dataclass(slots=True)
class RawFinding:
    scanner: str
    rule_id: str
    title: str
    severity: str  # critical | high | medium | low | info
    message: str = ""
    category: str = ""
    file: str | None = None
    line: int | None = None
    evidence: str | None = None  # untrusted: text from the scanned code
    fingerprint_hint: str | None = None  # the scanner's own stable id, if it has one


@dataclass(slots=True)
class ScannerRun:
    name: str
    state: str  # ok | skipped | error | not_applicable
    detail: str = ""
    findings: list[RawFinding] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)  # scanner-specific (e.g. a verdict)

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state,
            "detail": self.detail,
            "findings": len(self.findings),
        }


@dataclass(slots=True)
class ScanContext:
    settings: Settings
    profile: str
    source: str
    ref: str | None
    out_dir: Path
    tree: Path | None = None  # None when the scanner fetches the code itself


class Scanner:
    name: str = ""
    executable: str = ""

    def applies(self, ctx: ScanContext) -> bool:
        return True

    def run(self, ctx: ScanContext) -> ScannerRun:
        raise NotImplementedError


class SarifScanner(Scanner):
    """A command-line tool that reports in SARIF."""

    report_on_stdout = False
    severity_floor: str | None = None  # e.g. a leaked secret is never below "high"

    def command(self, ctx: ScanContext, out: Path) -> list[str]:
        raise NotImplementedError

    def not_applicable(self, res: proc.Result) -> bool:
        return False

    def run(self, ctx: ScanContext) -> ScannerRun:
        out = ctx.out_dir / f"{self.name}.sarif"
        res = proc.run(self.command(ctx, out), cwd=ctx.tree, timeout=ctx.settings.scanner_timeout)
        if self.not_applicable(res):
            return ScannerRun(self.name, "not_applicable")
        try:
            doc = json.loads(res.stdout if self.report_on_stdout else out.read_text("utf-8"))
        except (OSError, ValueError):
            tail = res.stderr.strip()[-400:]
            return ScannerRun(self.name, "error", f"no report (exit {res.returncode}): {tail}")
        findings = sarif.parse(doc, self.name, ctx.tree, floor=self.severity_floor)
        return ScannerRun(self.name, "ok", findings=findings)


def execute(scanner: Scanner, ctx: ScanContext) -> ScannerRun:
    """Run one scanner; a missing tool, crash or timeout becomes a state, not an exception."""
    if scanner.name in ctx.settings.disabled_scanners:
        return ScannerRun(scanner.name, "not_applicable", "disabled in settings")
    try:
        if not scanner.applies(ctx):
            return ScannerRun(scanner.name, "not_applicable")
        if shutil.which(scanner.executable) is None:
            return ScannerRun(scanner.name, "skipped", f"{scanner.executable} is not installed")
        return scanner.run(ctx)
    except subprocess.TimeoutExpired:
        return ScannerRun(scanner.name, "error", f"timed out after {ctx.settings.scanner_timeout}s")
    except Exception as exc:  # noqa: BLE001 - one scanner must not take the scan down
        return ScannerRun(scanner.name, "error", f"{type(exc).__name__}: {exc}"[:400])
