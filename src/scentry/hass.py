"""A deliberately narrow Home Assistant websocket client: it reads which Marketplace
(HACS) integrations and cards are installed, and what the Marketplace offers, and
nothing else.

HA has no read-only API for this: the commands need an admin user's token, and an admin
token can do almost anything in HA. So the commands this client may send are fixed in
code (`ALLOWED_COMMANDS`, `WATCH_SIGNALS`); nothing from a page, a scan or HA's own
answers ever becomes a command. The token lives only in the hass-sync container.

Commands, as Barkley (https://github.com/SeriesOfTubez/ha-barkley, MIT) found them in
Core's source: HA 2026.11+ ships the Marketplace in Core (`marketplace/...`); older HA
with the HACS custom integration answers `hacs/repositories/list` with the same fields.
"""

from __future__ import annotations

import contextlib
import json
import re
import ssl
from collections import deque
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from websockets.exceptions import WebSocketException
from websockets.sync.client import ClientConnection, connect

MARKETPLACE_LIST = "marketplace/repositories/list"  # HA 2026.11+
HACS_LIST = "hacs/repositories/list"  # older HA with the HACS custom integration
LIST_COMMANDS = (MARKETPLACE_LIST, HACS_LIST)
SUBSCRIBE = "marketplace/subscribe"
GET_CONFIG = "get_config"  # only to show the HA version on the status line
ALLOWED_COMMANDS = frozenset((*LIST_COMMANDS, SUBSCRIBE, GET_CONFIG))

# The Marketplace's dispatcher signals the sync listens to. An install (or update) that
# ended sends install_progress with progress: false; an uninstall sends a repository
# signal with action: uninstall. No event carries a version, so the list is read again.
SIGNAL_INSTALL_PROGRESS = "marketplace_repository_install_progress"
SIGNAL_REPOSITORY = "marketplace_repository"
WATCH_SIGNALS = (SIGNAL_INSTALL_PROGRESS, SIGNAL_REPOSITORY)

SCANNABLE = {"integration": "integration", "plugin": "card"}
MAX_MESSAGE = 64 * 1024 * 1024  # the whole catalog can be large
_BASE_URL = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+(:\d{1,5})?/?$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_VERSION = re.compile(r"^[A-Za-z0-9_.+/][A-Za-z0-9_.+/-]{0,99}$")  # never a leading "-"


class HassError(Exception):
    """Home Assistant couldn't be reached or didn't answer the way we need."""


def ws_url(base_url: str) -> str:
    """https://ha.example:8123 -> wss://ha.example:8123/api/websocket"""
    base = base_url.strip()
    if not _BASE_URL.match(base):
        raise HassError("SCENTRY_HASS_URL must look like http://192.168.1.10:8123 (no path)")
    parts = urlsplit(base)
    scheme = "wss" if parts.scheme == "https" else "ws"
    return f"{scheme}://{parts.netloc}/api/websocket"


def tls_context(verify: bool, ca_file: str = "") -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file or None)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


@dataclass(frozen=True, slots=True)
class Installed:
    """One installed Marketplace repository. Every value is validated: it comes from
    HA's data about third-party repositories and becomes a scan target."""

    repo: str  # owner/name
    kind: str  # integration | card
    name: str
    installed: str  # a tag, or a short commit for repositories without releases
    available: str  # what the Marketplace would install now ("" if unknown)

    @property
    def update(self) -> bool:
        return bool(self.available) and self.available != self.installed


def parse_installed(result: Any) -> tuple[list[Installed], dict[str, int]]:
    """Scannable installed items, plus counts of installed ones that aren't scanned
    (themes, python scripts, ...) by category."""
    if not isinstance(result, list):
        raise HassError("the Marketplace returned something other than a list")
    items: list[Installed] = []
    other: dict[str, int] = {}
    for r in result:
        if not isinstance(r, dict) or not r.get("installed"):
            continue
        category = str(r.get("category") or "")[:30] or "unknown"
        repo = str(r.get("full_name") or "")
        installed = str(r.get("installed_version") or "")
        available = str(r.get("available_version") or "")
        if category not in SCANNABLE:
            other[category] = other.get(category, 0) + 1
            continue
        if not _REPO.match(repo) or not _VERSION.match(installed):
            other["unreadable"] = other.get("unreadable", 0) + 1
            continue
        items.append(
            Installed(
                repo=repo,
                kind=SCANNABLE[category],
                name=str(r.get("name") or repo)[:100],
                installed=installed,
                available=available if _VERSION.match(available) else "",
            )
        )
    items.sort(key=lambda i: i.repo.lower())
    return items, other


@dataclass(frozen=True, slots=True)
class Listed:
    """One integration or card the Marketplace offers, installed or not. For searching
    in the portal; only `repo` and `version` ever reach a scan, both validated."""

    repo: str
    kind: str
    name: str
    description: str  # the publisher's text, shown escaped
    version: str  # what the Marketplace would install ("" if unknown)
    stars: int
    downloads: int | None
    installed: bool


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]+")


def _text(value: Any, limit: int) -> str:
    """Publisher text, one line: no control or bidi characters, cut to `limit`."""
    return " ".join(_CONTROL.sub(" ", str(value or "")).split())[:limit]


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def parse_catalog(result: Any) -> list[Listed]:
    """The scannable part of the whole catalog. Entries that don't validate are left out."""
    if not isinstance(result, list):
        raise HassError("the Marketplace returned something other than a list")
    out: dict[str, Listed] = {}
    for r in result:
        if not isinstance(r, dict) or r.get("category") not in SCANNABLE:
            continue
        repo = str(r.get("full_name") or "")
        if not _REPO.match(repo):
            continue
        version = str(r.get("available_version") or r.get("last_version") or "")
        out[repo.lower()] = Listed(
            repo=repo,
            kind=SCANNABLE[r["category"]],
            name=_text(r.get("name"), 100) or repo,
            description=_text(r.get("description"), 500),
            version=version if _VERSION.match(version) else "",
            stars=_count(r.get("stars")) or 0,
            downloads=_count(r.get("downloads")),
            installed=bool(r.get("installed")),
        )
    return sorted(out.values(), key=lambda i: i.repo.lower())


def matters(signal: str, data: dict[str, Any]) -> bool:
    """Whether an event means the installed list may have changed. The Marketplace's own
    refreshes send action "update" for every repository, so those are ignored."""
    if signal == SIGNAL_INSTALL_PROGRESS:
        return data.get("progress") is False
    if signal == SIGNAL_REPOSITORY:
        return data.get("action") == "uninstall"
    return False


class Connection:
    """One authenticated websocket to Home Assistant."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        verify_tls: bool = True,
        ca_file: str = "",
        timeout: float = 20,
    ):
        if not token:
            raise HassError("SCENTRY_HASS_TOKEN is not set")
        url = ws_url(base_url)
        self.timeout = timeout
        self._next_id = 0
        self._events: deque[tuple[str, dict[str, Any]]] = deque()
        self._subscriptions: dict[int, str] = {}
        self._stack = contextlib.ExitStack()
        try:
            self.ws: ClientConnection = self._stack.enter_context(connect(
                url,
                open_timeout=timeout,
                close_timeout=5,
                max_size=MAX_MESSAGE,
                ssl=tls_context(verify_tls, ca_file) if url.startswith("wss") else None,
                proxy=None,  # HA is on your network: never through an HTTP proxy
                user_agent_header="scentry",
            ))
        except (OSError, WebSocketException, TimeoutError) as exc:
            raise HassError(f"can't reach Home Assistant: {exc}") from exc
        try:
            if self._recv().get("type") != "auth_required":
                raise HassError("this doesn't look like Home Assistant's websocket")
            self._send({"type": "auth", "access_token": token})
            answer = self._recv()
            if answer.get("type") != "auth_ok":
                raise HassError("Home Assistant refused the token (SCENTRY_HASS_TOKEN)")
            self.ha_version = str(answer.get("ha_version") or "")[:40]
        except BaseException:
            self.close()
            raise

    # --- plumbing ----------------------------------------------------------------------

    def _send(self, message: dict[str, Any]) -> None:
        try:
            self.ws.send(json.dumps(message))
        except (OSError, WebSocketException) as exc:
            raise HassError(f"connection to Home Assistant lost: {exc}") from exc

    def _recv(self, timeout: float | None = None) -> dict[str, Any]:
        try:
            raw = self.ws.recv(timeout=self.timeout if timeout is None else timeout)
        except TimeoutError:
            raise
        except (OSError, WebSocketException) as exc:
            raise HassError(f"connection to Home Assistant lost: {exc}") from exc
        try:
            message = json.loads(raw)
        except ValueError as exc:
            raise HassError("Home Assistant sent something that isn't JSON") from exc
        return message if isinstance(message, dict) else {}

    def _keep_event(self, message: dict[str, Any]) -> None:
        if message.get("type") != "event":
            return
        signal = self._subscriptions.get(message.get("id"))  # type: ignore[arg-type]
        event = message.get("event")
        if signal is not None:
            self._events.append((signal, event if isinstance(event, dict) else {}))

    # --- the allowed calls ---------------------------------------------------------------

    def command(self, command: str, **params: Any) -> Any:
        """Send one allowed command and return its result. Events that arrive meanwhile
        are kept for next_event()."""
        if command not in ALLOWED_COMMANDS:
            raise HassError(f"command not allowed: {command}")
        self._next_id += 1
        mid = self._next_id
        self._send({"id": mid, "type": command, **params})
        while True:
            try:
                message = self._recv()
            except TimeoutError as exc:
                raise HassError(f"{command}: no answer from Home Assistant") from exc
            if message.get("id") == mid and message.get("type") == "result":
                break
            self._keep_event(message)
        if not message.get("success"):
            error = message.get("error") if isinstance(message.get("error"), dict) else {}
            code = str(error.get("code"))[:40]
            raise HassError(f"{command}: {code}: {str(error.get('message'))[:200]}")
        return message.get("result")

    def list_installed(self) -> tuple[list[Installed], dict[str, int], str]:
        """(installed items, skipped counts, the command that answered)."""
        result, command = self.list_repositories()
        return (*parse_installed(result), command)

    def list_repositories(self) -> tuple[Any, str]:
        """The whole catalog as HA lists it (installed or not), and the command that
        answered. Unvalidated: parse_installed / parse_catalog read it."""
        for command in LIST_COMMANDS:
            try:
                return self.command(command), command
            except HassError as exc:
                if "unknown_command" in str(exc):
                    continue  # not this HA's Marketplace: try the next one
                if "not_loaded" in str(exc):
                    raise HassError("the Marketplace hasn't finished loading yet") from exc
                if "unauthorized" in str(exc):
                    raise HassError(
                        "the token's user isn't an administrator; HA only lists the "
                        "Marketplace for admins"
                    ) from exc
                raise
        raise HassError("neither the Marketplace (HA 2026.11+) nor HACS answered")

    def subscribe(self) -> bool:
        """Listen for installs and uninstalls. False on an HA without marketplace/subscribe
        (the caller then relies on polling)."""
        for signal in WATCH_SIGNALS:
            try:
                self.command(SUBSCRIBE, signal=signal)
            except HassError as exc:
                if "unknown_command" in str(exc):
                    return False
                raise
            self._subscriptions[self._next_id] = signal
        return True

    def next_event(self, timeout: float) -> tuple[str, dict[str, Any]] | None:
        """The next subscribed event, or None after `timeout` seconds without one."""
        if self._events:
            return self._events.popleft()
        try:
            self._keep_event(self._recv(timeout))
        except TimeoutError:
            return None
        return self._events.popleft() if self._events else None

    def close(self) -> None:
        with contextlib.suppress(Exception):  # closing a dead socket is fine
            self._stack.close()
