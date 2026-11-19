"""SARIF 2.1.0 -> RawFinding. Everything in a SARIF file is untrusted text."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

from scentry.models import SEVERITY_RANK

if TYPE_CHECKING:
    from scentry.scanners.base import RawFinding

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_MAX_LINE_FILE = 2_000_000


def clean(text: Any, limit: int) -> str:
    text = _CONTROL.sub("", str(text or "")).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


# Evidence (a line of the scanned code) keeps its hidden characters as a mark, "<U+202E>",
# instead of losing them: a reviewer must see that the line holds one, or a bidi attack
# and a check against one both look like "". Not "\u202e": that's how code writes them
# itself, and a check written with escapes must still read differently from the
# characters. A mark is plain text, safe on any page and in any export.
MARK = re.compile(r"<U\+([0-9A-F]{4})>")


def evidence(text: Any, limit: int = 500) -> str:
    """A line (or a few) of the scanned code, as a finding keeps it."""
    text = str(text or "").replace("\r\n", "\n")
    text = _CONTROL.sub(lambda m: f"<U+{ord(m[0]):04X}>", text).strip()
    if len(text) <= limit:
        return text
    return re.sub(r"<U\+[0-9A-F]{0,3}$", "", text[:limit]) + "…"  # not half a mark


def hidden(code: str) -> bool:
    """Whether a mark's code point is one evidence marks (and clean() removes)."""
    return _CONTROL.match(chr(int(code, 16))) is not None


def unmarked(text: str) -> str:
    """Evidence without its marks: as it was kept before hidden characters were marked.
    Fingerprints are made of this, so a finding keeps its identity (and suppression)."""
    return MARK.sub(lambda m: "" if hidden(m[1]) else m[0], text)


# Advisory ids: CVE, GitHub, the Python, Go and Rust databases, OSV's own and malicious
# package reports. A rule named like one of these is a known vulnerability.
ADVISORY = re.compile(
    r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|"
    r"RUSTSEC-\d{4}-\d{4}|GO-\d{4}-\d{4,}|OSV-\d{4}-\d+|MAL-\d{4}-\d+|GSD-\d{4}-\d+)$",
    re.IGNORECASE,
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,59}$")  # any database's id, sanely shaped
_PACKAGE = re.compile(r"Package '([^'@\s]{1,200}|@[^'@\s]{1,200})@[^'\s]{1,100}'")


def vulns(ids: list[Any], package: Any = None) -> dict | None:
    """One vulnerability's ids as RawFinding.vulns, or None if none is an advisory id."""
    group = list(dict.fromkeys(str(i).upper() for i in ids if isinstance(i, str) and _ID.match(i)))
    if not any(ADVISORY.match(i) for i in group):
        return None
    pkg = clean(package, 200) or None if package else None
    return {"package": pkg, "groups": [group[:20]]}


def _relative(uri: str, tree: Path | None) -> str:
    """A result's file, relative to the scanned tree. Some tools (osv-scanner) give the
    absolute path, which would hold the scan's random work directory and change every
    finding's fingerprint on every scan."""
    path = unquote(re.sub(r"^file://", "", uri))
    if tree is not None:
        root = tree.resolve().as_posix().rstrip("/") + "/"
        for candidate in (path, path.lstrip("/")):
            if candidate.startswith(root):
                return candidate[len(root):]
    return path.lstrip("/")


def _text(node: Any) -> str:
    return (node or {}).get("text", "") if isinstance(node, dict) else ""


def _severity(result: dict, rule: dict, floor: str | None) -> str:
    sev = None
    for props in (result.get("properties"), rule.get("properties")):
        try:
            score = float((props or {}).get("security-severity"))
        except (TypeError, ValueError):
            continue
        sev = (
            "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4
            else "low" if score > 0 else "info"
        )  # fmt: skip
        break
    if sev is None:
        level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
        sev = _LEVELS.get(level or "warning", "medium")
    if floor and SEVERITY_RANK[floor] < SEVERITY_RANK[sev]:
        sev = floor
    return sev


def _line_from(tree: Path | None, file: str | None, line: int | None) -> str:
    """The source line a finding points at, if it is safely inside the tree."""
    if not (tree and file and line):
        return ""
    try:
        path = (tree / file).resolve()
        if not path.is_relative_to(tree.resolve()) or not path.is_file():
            return ""
        if path.stat().st_size > _MAX_LINE_FILE:
            return ""
        with path.open(encoding="utf-8", errors="replace") as fh:
            for number, text in enumerate(fh, 1):
                if number == line:
                    return text
    except OSError:
        pass
    return ""


def _same(a: str, b: str) -> bool:
    return " ".join(a.split()).rstrip(".").lower() == " ".join(b.split()).rstrip(".").lower()


def rule_details(rule: dict, title: str, message: str) -> dict | None:
    """What the tool says about a rule beyond the result's own message: its longer
    description (when it adds something) and its documentation, if that is an https link."""
    about = _text(rule.get("fullDescription")) or _text(rule.get("help"))
    if about and any(_same(about, x) for x in (title, message) if x):
        about = ""
    url = rule.get("helpUri")
    url = clean(url, 500) if isinstance(url, str) and url.startswith("https://") else ""
    if " " in url or "\\" in url:
        url = ""
    out = {k: v for k, v in (("about", clean(about, 1500)), ("url", url)) if v}
    return out or None


def parse(
    doc: dict, scanner: str, tree: Path | None = None, *, floor: str | None = None
) -> list[RawFinding]:
    from scentry.scanners.base import RawFinding

    out: list[RawFinding] = []
    for run in doc.get("runs") or []:
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
        for res in run.get("results") or []:
            index = res.get("ruleIndex")
            rule = rules[index] if isinstance(index, int) and 0 <= index < len(rules) else None
            rule_id = res.get("ruleId") or (rule or {}).get("id") or "unknown"
            rule = rule or by_id.get(rule_id) or {}

            file = line = None
            snippet = ""
            locations = res.get("locations") or []
            if locations:
                phys = (locations[0] or {}).get("physicalLocation") or {}
                uri = (phys.get("artifactLocation") or {}).get("uri") or ""
                file = _relative(str(uri), tree) or None
                region = phys.get("region") or {}
                line = region.get("startLine") if isinstance(region.get("startLine"), int) else None
                snippet = _text(region.get("snippet"))
            fps = res.get("partialFingerprints") or res.get("fingerprints") or {}
            # Semgrep without an account writes this placeholder instead of an id.
            fps = {k: v for k, v in fps.items() if v and v != "requires login"}
            title = _text(rule.get("shortDescription")) or rule.get("name") or rule_id
            hint = "|".join(f"{k}={fps[k]}" for k in sorted(fps)) if fps else None
            message = _text(res.get("message"))
            aliases = rule.get("deprecatedIds")  # osv-scanner lists a rule's aliases here
            aliases = aliases if isinstance(aliases, list) else []
            pkg = _PACKAGE.search(message)
            vuln = vulns([rule_id, *aliases], pkg[1] if pkg else None)
            details = rule_details(rule, title, message)

            out.append(
                RawFinding(
                    scanner=scanner,
                    rule_id=clean(rule_id, 300),
                    title=clean(title, 300),
                    severity=_severity(res, rule, floor),
                    message=clean(message, 2000),
                    file=clean(file, 1000) or None,
                    line=line,
                    evidence=evidence(snippet or _line_from(tree, file, line)) or None,
                    fingerprint_hint=hint,
                    vulns=vuln,
                    details=details,
                )
            )
    return out
