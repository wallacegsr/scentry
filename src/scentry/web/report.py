"""What a stored Barkley report says, in the shapes the portal's pages draw: an app's
data-flow diagram, the developer's security habits, a sentence and chips for an app's
card, and a finding's package facts and advisories.

After the app page of Barkley's own panel (sniff_test/ui.py, MIT), drawn the portal's
way: no scripts, no inline styles. Reads Scan.report and Scan.plain, Barkley's plain words
for it (scanners/barkley_plain.py). Names of sites, files and data in a report come from
the scanned code: untrusted text, escaped wherever a template shows it.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from scentry import sarif
from scentry.models import SEVERITY_RANK
from scentry.scanners import barkley

INTERNET_SKIP = {"local", "namespace", "link", "resolver"}  # not "sites it talks to"
CLASS_WORDS = {
    "declared": "one of the app's own",
    "undeclared": "not in the app's docs",
    "developer_hosted": "run by the developer",
    "analytics": "an analytics or crash-report service",
    "exfil_service": "a data-collection site",
    "messaging": "a messaging service",
    "public_ip": "a public IP address",
    "local": "on your own network",
    "link": "a project or help link",
    "infrastructure": "a package or project site",
    "resolver": "a DNS resolver",
    "namespace": "a name, not a connection",
}
KIND = {"integration": "Integration", "plugin": "Dashboard card", "card": "Dashboard card"}
HABITS_GRACE_DAYS = 7  # a dependency-update pull request this new isn't "left waiting"
STALE_YEARS = 2  # no release of a package for this long: likely unmaintained
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,59}$")


def words(scan: Any) -> dict:
    """Barkley's plain words for a scan's report; {} when there are none (not asked yet,
    or Barkley couldn't say)."""
    plain = getattr(scan, "plain", None)
    return plain if isinstance(plain, dict) and plain.get("version") == 1 else {}


def rule_words(plain: dict, rule_id: str) -> dict | None:
    """What Barkley's panel says about one of its rules: title, means, worry, chip, links."""
    r = (plain.get("rules") or {}).get(rule_id)
    return r if isinstance(r, dict) and r.get("title") else None


def _clip(text: Any, n: int) -> str:
    text = sarif.clean(text, 200)
    return text if len(text) <= n else text[: n - 1] + "…"


# --- the graph: where it connects, what it reads ---------------------------------------


def _graph(report: Any) -> tuple[dict, dict[str, dict], list[dict]]:
    g = report.get("graph") if isinstance(report, dict) else None
    g = g if isinstance(g, dict) else {}
    nodes = {n["id"]: n for n in g.get("nodes") or []
             if isinstance(n, dict) and isinstance(n.get("id"), str)}  # fmt: skip
    edges = [e for e in g.get("edges") or [] if isinstance(e, dict)
             and isinstance(e.get("relation"), str) and isinstance(e.get("target"), str)]
    return g, nodes, edges


def _where(edge: dict) -> list[str]:
    out = []
    for s in edge.get("samples") or []:
        if isinstance(s, dict) and s.get("file"):
            line = s.get("line")
            out.append(sarif.clean(f"{s['file']}:{line}" if isinstance(line, int) else s["file"],
                                   300))  # fmt: skip
    return out[:3]


def _attrs(edge: dict) -> dict:
    return edge["attrs"] if isinstance(edge.get("attrs"), dict) else {}


@dataclass
class Host:
    name: str  # untrusted
    cls: str
    where: list[str] = field(default_factory=list)  # untrusted
    schemes: list[str] = field(default_factory=list)

    @property
    def words(self) -> str:
        return CLASS_WORDS.get(self.cls, self.cls.replace("_", " "))


@dataclass
class Port:
    number: int
    name: str  # a well-known service on it, from Barkley's list; "" if none
    where: list[str]
    directions: list[str]

    @property
    def direction(self) -> str | None:
        """One clear direction ("out" or "in"), else None: unknown or mixed."""
        return self.directions[0] if len(set(self.directions)) == 1 else None


def hosts(report: Any) -> list[Host]:
    g, nodes, edges = _graph(report)
    out = []
    for e in edges:
        if e["relation"] == "connects_to" and e.get("source") == g.get("subject"):
            a = _attrs(e)
            name = (nodes.get(e["target"]) or {}).get("label") or e["target"]
            schemes = [sarif.clean(s, 10) for s in a.get("schemes") or [] if isinstance(s, str)]
            out.append(Host(sarif.clean(name, 200), str(a.get("class") or "undeclared"),
                            _where(e), schemes[:4]))  # fmt: skip
    return sorted(out, key=lambda h: h.name)


def ports(report: Any, plain: dict) -> list[Port]:
    _g, _nodes, edges = _graph(report)
    names = plain.get("ports") or {}
    out = []
    for e in edges:
        number = e["target"].split(":", 1)[-1]
        if e["relation"] == "uses_port" and number.isdigit():
            dirs = [d for d in _attrs(e).get("directions") or [] if d in ("in", "out")]
            out.append(Port(int(number), str(names.get(number, "")), _where(e), dirs))
    return sorted(out, key=lambda p: p.number)


def internet(hs: list[Host]) -> list[Host]:
    return [h for h in hs if h.cls not in INTERNET_SKIP]


def reads(report: Any) -> list[tuple[str, str, bool]]:
    """(node id, label, sensitive) of the user's data the app reads. Sensitive: a finding
    is attached (reading secrets, logins, other apps' passwords...)."""
    g, nodes, edges = _graph(report)
    out = []
    for e in edges:
        n = nodes.get(e["target"]) or {}
        if e["relation"] == "reads" and e.get("source") == g.get("subject") and n.get(
                "kind") in ("data", "auth"):  # fmt: skip
            out.append((e["target"], sarif.clean(n.get("label"), 200), bool(e.get("finding_ids"))))
    return sorted(out, key=lambda r: (not r[2], r[1]))


def flows(report: Any) -> list[dict]:
    return [e for e in _graph(report)[2] if e["relation"] == "flows_to"]


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _join(items: list[str]) -> str:
    return " and ".join(items) if len(items) <= 2 else ", ".join(items[:-1]) + " and " + items[-1]


def port_phrase(pts: list[Port]) -> str:
    """'port 6668 (Tuya local)' / 'ports 502 (Modbus) and 8000'."""
    named = [f"{p.number} ({p.name})" if p.name else str(p.number) for p in pts[:3]]
    more = f" and {len(pts) - 3} more" if len(pts) > 3 else ""
    return ("port " if len(pts) == 1 else "ports ") + _join(named) + more


def connection_sentence(report: Any, plain: dict) -> str:
    """Where the code says it connects, in a sentence: sites, your own network, ports."""
    hs, pts = hosts(report), ports(report, plain)
    net, home = internet(hs), [h for h in hs if h.cls == "local"]
    if net:
        s = f"Names {_plural(len(net), 'internet site')}"
        s += " and addresses on your own network." if home else " in its code."
    elif home:
        s = "Names no internet sites, only addresses on your own network."
    else:
        s = "No internet sites in its code."
    if pts:
        dirs = {p.direction for p in pts}
        if dirs == {"out"}:
            s += f" Connects to {port_phrase(pts)} on a device or server it's set up with."
        elif dirs == {"in"}:
            s += f" Listens on {port_phrase(pts)}."
        else:
            s += f" Its code names {port_phrase(pts)}."
    return s


# --- the data-flow diagram -------------------------------------------------------------


@dataclass
class Shape:
    """One element of the diagram's SVG; the template draws it (escaping the text)."""

    kind: str  # rect | text | line | path
    cls: str = ""
    x: float = 0
    y: float = 0
    w: float = 0
    h: float = 0
    x2: float = 0
    y2: float = 0
    d: str = ""
    text: str = ""
    anchor: str = ""  # text-anchor: "middle", or "" for the start
    marker: str = ""  # an arrowhead at the end: "red" | "grey" | ""


@dataclass
class Diagram:
    width: int
    height: int
    shapes: list[Shape]
    suffix: str  # keeps the arrowheads' ids apart, two drawings on one page


@dataclass
class Dest:
    key: str  # a node id (a flow's destination), or home | ports | dev | net
    title: str
    sub: str
    cls: str = ""  # bad | priv | ""


@dataclass
class Flow:
    wide: Diagram  # side by side, for wide screens
    narrow: Diagram  # stacked, for phones (the stylesheet shows one)
    caption: list[str]
    label: str


@dataclass
class _Data:
    reads: list[tuple[str, str, str, str]]  # (node id, title, raw label, box class)
    dests: list[Dest]
    flows: list[dict]
    extra: int  # flow destinations beyond the three drawn
    port_dirs: set[str | None]


def _data(report: Any, plain: dict) -> _Data | None:
    labels = plain.get("data_labels") or {}
    fl = flows(report)
    sources = {e.get("source") for e in fl}
    rd = [(nid, sarif.clean(labels.get(label) or label, 100), label,
           "bad" if nid in sources else ("sens" if sens else ""))
          for nid, label, sens in reads(report)[:6]]  # fmt: skip
    _g, nodes, _edges = _graph(report)
    hs, pts = hosts(report), ports(report, plain)
    dests: list[Dest] = []
    targets: list[str] = []
    for e in fl:
        if e["target"] not in targets:
            targets.append(e["target"])
    for t in targets[:3]:
        n = nodes.get(t) or {}
        if n.get("kind") == "network":
            dests.append(Dest(t, "Somewhere off your box", "destination not in the code", "bad"))
        else:
            dests.append(Dest(t, _clip(n.get("label") or t, 26), "unexplained site", "bad"))
    home = [h for h in hs if h.cls == "local"]
    if home:
        dests.append(Dest("home", "Your own network", _plural(len(home), "address", "addresses")))
    if pts:
        dirs = {p.direction for p in pts}
        if dirs == {"in"}:
            title = (f"Listens on port {pts[0].number}" if len(pts) == 1
                     else f"Listens on {len(pts)} ports")  # fmt: skip
            sub = "others connect to this machine"
        elif len(pts) == 1:
            p = pts[0]
            title = (f"{p.name} server, port {p.number}" if p.name
                     else f"A server on port {p.number}")  # fmt: skip
            sub = "its address isn't in the code"
        else:
            title = f"{len(pts)} servers or devices"
            nums = ", ".join(str(p.number) for p in pts[:4]) + (" …" if len(pts) > 4 else "")
            sub = f"{nums} · address unknown"
        dests.append(Dest("ports", title, sub))
    flowing = {(nodes.get(t) or {}).get("label") for t in targets}
    net = [h for h in internet(hs) if h.name not in flowing]
    dev = [h for h in net if h.cls in ("developer_hosted", "analytics")]
    if dev:
        kinds = {h.cls for h in dev}
        if len(dev) == 1:
            title = ("Server the developer runs" if "developer_hosted" in kinds
                     else "Analytics service")  # fmt: skip
        elif kinds == {"developer_hosted"}:
            title = f"{len(dev)} servers the developer runs"
        elif kinds == {"analytics"}:
            title = f"{len(dev)} analytics services"
        else:
            title = f"{len(dev)} developer or analytics servers"
        dests.append(Dest("dev", title, _clip(dev[0].name, 30), "priv"))
    rest = [h for h in net if h not in dev]
    if rest:
        own = sum(1 for h in rest if h.cls == "declared")
        sub = f"{own} named in the app's docs" if own else "none named in the app's docs"
        dests.append(Dest("net", f"{'Other internet' if dev else 'Internet'} sites: {len(rest)}",
                          sub))  # fmt: skip
    if not rd and not dests:
        return None
    return _Data(rd, dests, fl, len(targets) - 3, {p.direction for p in pts})


def _box(x: float, y: float, w: float, title: str, sub: str, cls: str,
         chars: int) -> list[Shape]:  # fmt: skip
    return [Shape("rect", f"box {cls}".strip(), x=x, y=y, w=w, h=44),
            Shape("text", "", x=x + 12, y=y + 19, text=_clip(title, chars)),
            Shape("text", "sm", x=x + 12, y=y + 35, text=_clip(sub, chars + 1))]  # fmt: skip


def _app(x: float, cy: float, name: str, kind: str) -> list[Shape]:
    return [Shape("rect", "box app", x=x, y=cy - 28, w=170, h=56),
            Shape("text", "nm", x=x + 85, y=cy - 3, text=_clip(name, 21), anchor="middle"),
            Shape("text", "sm", x=x + 85, y=cy + 13, text=kind, anchor="middle")]  # fmt: skip


def _way(d: _Data, key: str) -> str | None:
    """Who opens the connection: "out" to a site or server, "in" for a port it listens on,
    None when the code doesn't make that clear."""
    if key != "ports":
        return "out"
    return next(iter(d.port_dirs)) if len(d.port_dirs) == 1 else None


def _leak(e: dict) -> str:
    return "leak" if e.get("evidence") == "proven" else "leak maybe"


def _wide(d: _Data, name: str, kind: str) -> Diagram:
    """Left: what it reads. Middle: the app. Right: where it can connect."""
    row_h, top, w = 56, 10, 700
    rows = max(len(d.reads), len(d.dests), 2)
    height = top * 2 + rows * row_h
    cy = top + rows * row_h / 2

    def ys(n: int) -> list[float]:
        return [cy - n * row_h / 2 + i * row_h + 6 for i in range(n)]

    shapes: list[Shape] = []
    left: dict[str, float] = {}
    for (nid, title, label, cls), y in zip(d.reads, ys(len(d.reads)), strict=True):
        shapes += _box(6, y, 176, title, label, cls, 22)
        shapes.append(Shape("line", "wire dash", x=182, y=y + 22, x2=258, y2=cy, marker="grey"))
        left[nid] = y + 22
    if not d.reads:
        shapes.append(Shape("text", "sm", x=6, y=cy + 4, text="Reads none of your private data"))
    app_at = len(shapes)
    shapes += _app(260, cy, name, kind)
    right: dict[str, float] = {}
    for dest, y in zip(d.dests, ys(len(d.dests)), strict=True):
        shapes += _box(w - 200, y, 194, dest.title, dest.sub, dest.cls, 26)
        way = _way(d, dest.key)
        if way == "in":
            shapes.append(Shape("line", "wire", x=w - 200, y=y + 22, x2=432, y2=cy, marker="grey"))
        else:
            shapes.append(Shape("line", "wire", x=430, y=cy, x2=w - 202 if way else w - 200,
                                y2=y + 22, marker="grey" if way else ""))  # fmt: skip
        right[dest.key] = y + 22
    leaks = [Shape("path", _leak(e), marker="red",
                   d=f"M182 {y1:.0f} C 330 {y1:.0f}, 380 {y2:.0f}, {w - 202} {y2:.0f}")
             for e in d.flows
             if (y1 := left.get(e.get("source"))) is not None
             and (y2 := right.get(e["target"])) is not None]  # fmt: skip
    shapes[app_at:app_at] = leaks  # under the app's box, so its name stays readable
    return Diagram(w, int(height), shapes, "w")


def _narrow(d: _Data, name: str, kind: str) -> Diagram:
    """The same picture stacked for a phone: reads, the app, then where it connects. The
    grey connectors run down the right margin (no line crosses a box), the red paths down
    the left one."""
    row_h, top, w, bx, bw = 52, 8, 360, 40, 280
    spine, red_x, mid = w - 20, 12, w / 2
    y_reads = top
    reads_end = y_reads + len(d.reads) * row_h if d.reads else y_reads + 24
    cy = reads_end + 56
    y_dest = cy + 56
    height = y_dest + max(len(d.dests), 1) * row_h
    shapes: list[Shape] = []
    left: dict[str, float] = {}
    for i, (nid, title, label, cls) in enumerate(d.reads):
        y = y_reads + i * row_h
        shapes += _box(bx, y, bw, title, label, cls, 34)
        shapes.append(Shape("line", "wire dash", x=bx + bw, y=y + 22, x2=spine, y2=y + 22))
        left[nid] = y + 22
    if d.reads:
        shapes.append(Shape("path", "wire dash", marker="grey",
                            d=f"M{spine} {y_reads + 22} V{cy - 44} H{mid:.0f} V{cy - 30}"))
    else:
        shapes.append(Shape("text", "sm", x=bx, y=y_reads + 14,
                            text="Reads none of your private data"))  # fmt: skip
    app_at = len(shapes)
    shapes += _app(mid - 85, cy, name, kind)
    right: dict[str, float] = {}
    if d.dests:
        last = y_dest + (len(d.dests) - 1) * row_h + 22
        shapes.append(Shape("path", "wire", d=f"M{mid:.0f} {cy + 28} V{cy + 44} H{spine} V{last}"))
    for i, dest in enumerate(d.dests):
        y = y_dest + i * row_h
        shapes += _box(bx, y, bw, dest.title, dest.sub, dest.cls, 38)
        way = _way(d, dest.key)
        if way == "in":  # others connect in: the arrow points from the box to the spine
            shapes.append(Shape("line", "wire", x=bx + bw, y=y + 22, x2=spine - 1, y2=y + 22,
                                marker="grey"))  # fmt: skip
        else:
            shapes.append(Shape("line", "wire", x=spine, y=y + 22, y2=y + 22,
                                x2=bx + bw + 2 if way else bx + bw,
                                marker="grey" if way else ""))  # fmt: skip
        right[dest.key] = y + 22
    leaks = [Shape("path", _leak(e), marker="red",
                   d=f"M{bx} {y1:.0f} C {red_x} {y1:.0f}, {red_x} {y2:.0f}, {bx - 2} {y2:.0f}")
             for e in d.flows
             if (y1 := left.get(e.get("source"))) is not None
             and (y2 := right.get(e["target"])) is not None]  # fmt: skip
    shapes[app_at:app_at] = leaks
    return Diagram(w, int(height), shapes, "n")


def flow(report: Any, plain: dict, name: str) -> Flow | None:
    """The data-flow diagram: what the app reads (left), the app, and where it can connect
    (right). A red line only where Barkley found a path from your data to that place:
    solid when traced in the code, dashed when possible. None: it reads none of your data
    and names no address."""
    d = _data(report, plain)
    if d is None:
        return None
    target = report.get("target") if isinstance(report.get("target"), dict) else {}
    kind = KIND.get(str(target.get("kind")), "")
    if d.flows:
        caption = ["Red, solid: a path from your data traced in the code.",
                   "Red, dashed: it reads that data and can reach an unexplained site; the "
                   "path isn't proven."]  # fmt: skip
        if d.extra > 0:
            caption.append(f"{_plural(d.extra, 'more destination')} in the list below.")
    else:
        caption = ["Arrows: which way the connection goes. No path found from your data to the "
                   "internet."]  # fmt: skip
    return Flow(_wide(d, name, kind), _narrow(d, name, kind), caption,
                f"Where {name}'s data can go")  # fmt: skip


# --- the developer's security habits ---------------------------------------------------

_SCAN_KIND = {"code": "code", "deps": "dependencies", "secrets": "leaked secrets",
              "practices": "security practices"}  # fmt: skip
_ECO = {"pip": "Python packages", "npm": "JavaScript packages",
        "github-actions": "GitHub Actions", "docker": "Docker images"}  # fmt: skip


@dataclass
class Habit:
    mark: str  # yes | no | warn | "" (a fact)
    text: str
    code: str = ""  # a file name, shown as code after the text
    after: str = ""
    issues: list[dict] = field(default_factory=list)  # {number, title, age, url}


def _ago(days: Any) -> str:
    if not isinstance(days, int):
        return ""
    if days < 1:
        return "opened today"
    if days < 60:
        return f"{_plural(days, 'day')} old"
    return f"{days // 30} months old"


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def habits(report: Any) -> tuple[list[Habit], bool] | None:
    """What the app's own repository shows about keeping it safe, and whether every
    check is green (A+). Context only: never scored. None: Barkley didn't look (a local
    folder, or a report from before it did)."""
    h = report.get("hygiene") if isinstance(report, dict) else None
    if not isinstance(h, dict):
        return None
    target = report.get("target") if isinstance(report.get("target"), dict) else {}
    repo = str(target.get("repo") or "")
    out: list[Habit] = []
    scanners = [s for s in h.get("scanners") or [] if isinstance(s, dict)]
    if scanners:
        names = ", ".join(f"{sarif.clean(s.get('name'), 40)} "
                          f"({_SCAN_KIND.get(s.get('kind'), 'checks')})" for s in scanners[:8])
        out.append(Habit("yes", f"Runs security scans in its GitHub workflows: {names}."))
    else:
        out.append(Habit("no", "No security scanner in its GitHub workflows (CodeQL, Semgrep, "
                               "Bandit, Trivy, OSV-Scanner, pip-audit, Gitleaks…)."))  # fmt: skip
    dependabot = h.get("dependabot")
    if isinstance(dependabot, list):
        what = ", ".join(_ECO.get(x, sarif.clean(x, 30)) for x in dependabot[:6]
                         if isinstance(x, str)) or "its dependencies"  # fmt: skip
        out.append(Habit("yes", f"Dependabot is set up to propose updates for {what}."))
    if h.get("renovate"):
        out.append(Habit("yes", "Renovate is set up to propose dependency updates."))
    if not isinstance(dependabot, list) and not h.get("renovate"):
        out.append(Habit("no", "No Dependabot or Renovate set up for dependency updates."))
    if h.get("security_policy"):
        out.append(Habit("yes", "Has a security policy,",
                         code=sarif.clean(h["security_policy"], 100),
                         after=", saying how to report a problem privately."))  # fmt: skip
    else:
        out.append(Habit("no", "No SECURITY.md telling people how to report a problem privately."))
    prs = h.get("update_prs")
    if isinstance(prs, dict) and prs.get("off"):
        out.append(Habit("no", "Pull requests are turned off on this repository."))
    elif isinstance(prs, dict):
        n, oldest = _int(prs.get("open")), prs.get("oldest_days")
        if n and isinstance(oldest, int) and oldest < HABITS_GRACE_DAYS:
            out.append(Habit("yes", "No dependency-update pull requests left waiting: "
                             f"{n} opened in the last {HABITS_GRACE_DAYS} days."))  # fmt: skip
        elif n:
            old = _ago(oldest)
            out.append(Habit("", f"Dependency-update pull requests waiting to be merged: {n}"
                                 + (f", the oldest {old}" if old else "") + "."))  # fmt: skip
        elif isinstance(dependabot, list) or h.get("renovate"):
            out.append(Habit("yes", "No dependency-update pull requests left waiting."))
    issues = h.get("security_issues")
    if isinstance(issues, dict) and issues.get("off"):
        out.append(Habit("no", "Issues are turned off on this repository, so there's no public "
                               "place to report a problem."))  # fmt: skip
    elif isinstance(issues, dict):
        n, of = _int(issues.get("open")), _int(issues.get("of"))
        if n:
            among = " (among the 100 newest open issues)" if of >= 100 else ""
            items = [{"number": it["number"], "title": sarif.clean(it.get("title"), 200),
                      "age": _ago(it.get("age_days")),
                      "url": f"https://github.com/{repo}/issues/{it['number']}"
                      if _REPO.match(repo) else ""}
                     for it in issues.get("items") or []
                     if isinstance(it, dict) and _int(it.get("number")) > 0][:10]  # fmt: skip
            out.append(Habit("", f"Open issues that look security-related: {n}{among}.",
                             issues=items))  # fmt: skip
        else:
            out.append(Habit("yes", "No open issue labeled or titled as a security problem "
                                    f"({_plural(of, 'open issue')} checked)."))  # fmt: skip
    if h.get("dependabot_but_known_vulns"):
        out.append(Habit("warn", "Dependabot watches these dependencies, yet this version ships "
                                 "some with known vulnerabilities (see the findings). Either an "
                                 "alert wasn't acted on, or the fix came after this release."))
    for err in (h.get("errors") or [])[:5]:
        out.append(Habit("", f"Not checked: {sarif.clean(err, 300)}"))
    return out, all_green(h)


def all_green(h: dict) -> bool:
    """A+ security habits: every check green. A dependency-update pull request younger
    than HABITS_GRACE_DAYS doesn't count against it."""
    prs, issues = h.get("update_prs"), h.get("security_issues")
    if h.get("errors") or not isinstance(prs, dict) or prs.get("off"):
        return False
    oldest = prs.get("oldest_days")
    if _int(prs.get("open")) and not (isinstance(oldest, int) and oldest < HABITS_GRACE_DAYS):
        return False
    return (bool(h.get("scanners")) and (isinstance(h.get("dependabot"), list)
            or bool(h.get("renovate"))) and bool(h.get("security_policy"))
            and isinstance(issues, dict) and not issues.get("off")
            and not _int(issues.get("open"))
            and not h.get("dependabot_but_known_vulns"))  # fmt: skip


# --- an app's card ---------------------------------------------------------------------

BIG = ("critical", "high", "medium")


def _worst_rules(open_findings: list) -> list[list]:
    """Open findings by rule, the worst rule first (duplicates of another left out)."""
    by: dict[str, list] = {}
    for f in open_findings:
        if f.same_as is None:
            by.setdefault(f.rule_id, []).append(f)
    return sorted(by.values(), key=lambda fs: (min(SEVERITY_RANK.get(f.severity, 9) for f in fs),
                                                fs[0].title))  # fmt: skip


def _rule_title(f: Any, plain: dict) -> str:
    r = rule_words(plain, f.rule_id) if f.scanner == "barkley" else None
    return r["title"] if r else f.title


def card_sentence(profile: str, scan: Any, open_findings: list, plain: dict) -> str:
    """What a card says about an app or repository, in a sentence or two."""
    if scan is None:
        return "Not scanned yet."
    if not scan.complete:
        first = "The last scan didn't finish, so it may be missing something."
    else:
        big = [fs for fs in _worst_rules(open_findings) if fs[0].severity in BIG]
        if big:
            first = _rule_title(min(big[0], key=lambda f: SEVERITY_RANK.get(f.severity, 9)),
                                plain).rstrip(".") + "."  # fmt: skip
            if len(big) > 1:
                first += f" And {_plural(len(big) - 1, 'more thing')} worth a look."
        elif open_findings and profile == "owned":
            first = "Only minor findings open."
        else:
            first = "No security concerns found." if profile == "ha" else "No open findings."
    report = scan.report if isinstance(scan.report, dict) else None
    if not report or not report.get("graph"):
        return first
    notes = [n for n in plain.get("privacy") or [] if isinstance(n, dict) and n.get("title")]
    if notes:
        second = notes[0]["title"].rstrip(".")
        if len(notes) > 1:
            second += f", plus {_plural(len(notes) - 1, 'more privacy note')}"
        return f"{first} {second}."
    return f"{first} {connection_sentence(report, plain)}"


def card_chips(scan: Any, open_findings: list, plain: dict) -> list[tuple[str, str]]:
    """Each chip can change a decision: the worst kinds of open findings, then privacy
    notes. The sentence already says where the app connects."""
    chips: list[tuple[str, str]] = []
    for fs in _worst_rules(open_findings):
        f = fs[0]
        if f.severity not in BIG or len(chips) >= 3:
            break
        r = rule_words(plain, f.rule_id) if f.scanner == "barkley" else None
        chip = (r or {}).get("chip") or _clip(f.title, 36)
        cls = "bad" if f.severity in ("critical", "high") else "warn"
        if (cls, chip) not in chips:
            chips.append((cls, chip))
    if scan is not None and scan.complete:
        for n in plain.get("privacy") or []:
            if isinstance(n, dict) and n.get("label"):
                chips.append(("priv", n["label"]))
    return chips


# --- a finding's package and advisories ------------------------------------------------


def report_finding(report: Any, finding: Any) -> dict | None:
    """The finding of a Barkley report that a Scentry finding was made from: same rule,
    place and evidence, as the scan kept them."""
    if not isinstance(report, dict) or finding.scanner != "barkley":
        return None
    for x in report.get("findings") or []:
        if not isinstance(x, dict):
            continue
        raw = barkley.raw_finding(x)
        if (raw.rule_id, raw.file, raw.line, raw.evidence) == (
                finding.rule_id, finding.file, finding.line, finding.evidence):  # fmt: skip
            return x
    return None


@dataclass
class Bug:
    id: str
    url: str
    also: list[str]  # its CVE ids
    summary: str = ""


@dataclass
class Package:
    name: str
    version: str
    ecosystem: str
    facts: list[str]  # fixed in..., the newest is..., listed by the app itself...
    stale: str
    fixed: str
    bugs: list[Bug]


def bug(vid: str, also: list | tuple = (), summary: str = "") -> Bug | None:
    """One advisory: its id linked to its record on OSV (every database's ids are there),
    other ids for it alongside."""
    vid = sarif.clean(vid, 60)
    if not _ID.match(vid):
        return None
    others = [sarif.clean(a, 40) for a in also if isinstance(a, str) and a != vid][:3]
    return Bug(vid, f"https://osv.dev/vulnerability/{quote(vid)}", others,
               sarif.clean(summary, 300))  # fmt: skip


def bugs_of(vulns: Any) -> list[Bug]:
    """Advisories from a finding's vulnerability ids (any scanner), one per vulnerability:
    a GitHub, Python or other database's id linked (CVE records are thinner there), the
    rest alongside."""
    out = []
    for g in (vulns.get("groups") if isinstance(vulns, dict) else None) or []:
        ids = [str(i) for i in g if isinstance(i, str)] if isinstance(g, list) else []
        if ids:
            first = next((i for i in ids if not i.upper().startswith("CVE-")), ids[0])
            if b := bug(first, [i for i in ids if i != first]):
                out.append(b)
    return out[:10]


def years_since(day: Any, today: datetime.date) -> int | None:
    try:
        then = datetime.date.fromisoformat(str(day)[:10])
    except ValueError:
        return None
    return (today - then).days // 365


def package(dep: Any, owned: bool, today: datetime.date) -> Package | None:
    """One vulnerable package of a Barkley finding: is there a fix, is the app on the newest
    release, does the app itself ask for it. Facts from OSV and the package's registry."""
    if not isinstance(dep, dict) or not dep.get("package"):
        return None
    fixed = sarif.clean(dep.get("fixed_in"), 60)
    facts = [f"fixed in {fixed}" if fixed else "no release fixes it yet"]
    version, latest = sarif.clean(dep.get("version"), 60), sarif.clean(dep.get("latest"), 60)
    when = sarif.clean(dep.get("latest_date"), 20)
    on = f" ({when})" if when else ""
    if latest and latest == version:
        facts.append(f"it is the newest release{on}")
    elif latest:
        n = _int(dep.get("behind"))
        newer = f", {_plural(n, 'release')} newer" if n else ""
        facts.append(f"the newest is {latest}{on}{newer}")
    elif dep.get("lookup_error"):
        facts.append("the newest release couldn't be looked up")
    if dep.get("direct") is True:
        facts.append("your code asks for it itself" if owned else "the app asks for it itself")
    elif dep.get("direct") is False:
        facts.append("it comes in through another library")
    stale = ""
    age = years_since(when, today) if latest and when else None
    if age is not None and age >= STALE_YEARS:
        stale = f"No release in over {_plural(age, 'year')}: likely unmaintained"
        stale += ", so a fix may never come." if not fixed else "."
    bugs = [b for a in (dep.get("advisories") or [])[:10] if isinstance(a, dict)
            and (b := bug(str(a.get("id") or ""), [x for x in a.get("aliases") or []
                                                   if str(x).upper().startswith("CVE-")],
                          a.get("summary") or str(a.get("details") or "")[:200]))]  # fmt: skip
    return Package(sarif.clean(dep["package"], 120), version, sarif.clean(dep.get("ecosystem"), 20),
                   facts, stale, fixed, bugs)  # fmt: skip


def package_action(pkg: Package, owned: bool) -> str:
    """What you can do about a vulnerable package: update it in your own code; in an app,
    ask its developer."""
    if owned:
        if pkg.fixed:
            return (f"Update {pkg.name} to {pkg.fixed} or later. If it comes in through another "
                    "library, update that one, or pin the fixed version.")  # fmt: skip
        return (f"No release of {pkg.name} fixes it yet: check whether your code reaches the "
                "affected part, and watch for a fix.")  # fmt: skip
    if pkg.ecosystem == "npm":
        return ("The library is built into the card's code, so you can't update it yourself. If "
                "the bug matters for how the card uses it, ask the developer to update or "
                "replace it: Share fills in a GitHub issue.")  # fmt: skip
    return ("Home Assistant installs the version the integration asks for, so a change you make "
            "yourself doesn't last. If the bug matters for how the integration uses it, ask the "
            "developer to update or replace it: Share fills in a GitHub issue.")  # fmt: skip
