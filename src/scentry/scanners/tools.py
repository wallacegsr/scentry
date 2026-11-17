"""The general-purpose scanners, all SARIF command-line tools."""

from __future__ import annotations

from pathlib import Path

from scentry import proc
from scentry.scanners.base import SarifScanner, ScanContext


def _has(tree: Path | None, pattern: str) -> bool:
    return tree is not None and next(tree.rglob(pattern), None) is not None


class Semgrep(SarifScanner):
    """SAST across most languages."""

    name = executable = "semgrep"

    def command(self, ctx: ScanContext, out: Path) -> list[str]:
        cmd = [
            "semgrep", "scan", "--config", ctx.settings.semgrep_config, "--sarif",
            "--output", str(out), "--metrics=off", "--disable-version-check", "--quiet",
        ]  # fmt: skip
        if not ctx.settings.honor_repo_ignores:
            cmd.append("--disable-nosem")
        return [*cmd, "."]


class Gitleaks(SarifScanner):
    """Secrets, through the whole git history when there is one. Values are redacted."""

    name = executable = "gitleaks"
    severity_floor = "high"

    def command(self, ctx: ScanContext, out: Path) -> list[str]:
        mode = "git" if ctx.tree and (ctx.tree / ".git").exists() else "dir"
        return [
            "gitleaks", mode, "--redact", "--no-banner", "--exit-code", "0",
            "--report-format", "sarif", "--report-path", str(out), ".",
        ]  # fmt: skip


class OsvScanner(SarifScanner):
    """Known vulnerabilities in the dependencies named by lockfiles and manifests."""

    name = "osv-scanner"
    executable = "osv-scanner"

    def command(self, ctx: ScanContext, out: Path) -> list[str]:
        return [
            "osv-scanner", "scan", "source", "--recursive",
            "--format", "sarif", "--output", str(out), ".",
        ]  # fmt: skip

    def not_applicable(self, res: proc.Result) -> bool:
        return res.returncode == 128  # no package sources found


class Trivy(SarifScanner):
    """Dockerfile, compose, Kubernetes and Terraform misconfiguration. Dependency
    vulnerabilities are left to osv-scanner so the same CVE isn't reported twice."""

    name = executable = "trivy"

    def command(self, ctx: ScanContext, out: Path) -> list[str]:
        return [
            "trivy", "fs", "--scanners", "misconfig", "--skip-version-check",
            "--format", "sarif", "--output", str(out), "--quiet", ".",
        ]  # fmt: skip


class Zizmor(SarifScanner):
    """GitHub Actions workflows: injection, over-broad permissions, unpinned actions."""

    name = executable = "zizmor"
    report_on_stdout = True

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.tree is not None and (ctx.tree / ".github" / "workflows").is_dir()

    def command(self, ctx: ScanContext, out: Path) -> list[str]:
        return ["zizmor", "--offline", "--no-exit-codes", "--format", "sarif", "."]


class Bandit(SarifScanner):
    """Python-specific security lint. B101 (use of assert) is skipped: it fires on
    every test and says nothing about security."""

    name = executable = "bandit"

    def applies(self, ctx: ScanContext) -> bool:
        return _has(ctx.tree, "*.py")

    def command(self, ctx: ScanContext, out: Path) -> list[str]:
        cmd = ["bandit", "-r", ".", "-f", "sarif", "-o", str(out), "--exit-zero", "-q",
               "--skip", "B101"]  # fmt: skip
        if not ctx.settings.honor_repo_ignores:
            cmd.append("--ignore-nosec")
        return cmd
