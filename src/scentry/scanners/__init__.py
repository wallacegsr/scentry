"""Scanner registry: which scanners a profile runs, in order."""

from __future__ import annotations

from scentry.scanners.barkley import Barkley
from scentry.scanners.base import RawFinding, ScanContext, Scanner, ScannerRun, execute
from scentry.scanners.tools import Bandit, Gitleaks, OsvScanner, Semgrep, Trivy, Zizmor

PROFILE_SCANNERS: dict[str, tuple[type[Scanner], ...]] = {
    # Your own code: every general scanner, plus Barkley when the repository holds a
    # Home Assistant integration or card.
    "owned": (Semgrep, Gitleaks, OsvScanner, Trivy, Zizmor, Bandit, Barkley),
    # Someone else's Home Assistant integration or card: Barkley's verdict.
    "ha": (Barkley,),
}


def scanners_for(profile: str) -> list[Scanner]:
    return [cls() for cls in PROFILE_SCANNERS[profile]]


__all__ = [
    "PROFILE_SCANNERS", "RawFinding", "ScanContext", "Scanner", "ScannerRun",
    "execute", "scanners_for",
]  # fmt: skip
