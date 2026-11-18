"""The services' log, also kept in the database for the portal's Log page (System › Log):
what each service did and what went wrong, searchable in one place rather than in each
container's output (which still gets every line, as before).

Kept: Scentry's own messages from INFO up, and warnings and errors from anything else (a
library, the web server). Not the web server's access log, and nothing from the database
library: its messages would be about writing this log. The secrets this service holds
(tokens, passwords, notification URLs) are blanked before a message is stored.

A background thread writes the messages in batches. When the database can't take them
they're dropped, after one line on the console: the log must never hold a service up.
The web service also clears out old ones: older than SCENTRY_LOG_DAYS, and beyond the
newest KEEP_ROWS.
"""

from __future__ import annotations

import contextlib
import datetime
import logging
import queue
import re
import sys
import threading
import time
from collections.abc import Iterable

from sqlalchemy import delete, func, insert, select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import Session

from scentry import db
from scentry.config import Settings
from scentry.models import LogEntry, utcnow

SERVICES = ("web", "runner", "hass-sync", "notify", "ai")
KEEP_ROWS = 100_000
MESSAGE_MAX = 10_000  # a longer one (a deep traceback) keeps its start and its end
BATCH = 200
QUEUE_MAX = 10_000  # a flood beyond this isn't kept (it's still on the console)
PRUNE_SECONDS = 3600
REDACTED = "[redacted]"
_MIN_SECRET = 6  # a shorter value would blank ordinary words
_STOP = object()


def wanted(record: logging.LogRecord) -> bool:
    name = record.name
    if name == "scentry" or name.startswith("scentry."):
        return record.levelno >= logging.INFO
    if name.startswith(("sqlalchemy", "uvicorn.access")):
        return False
    return record.levelno >= logging.WARNING


def secrets_of(settings: Settings) -> list[str]:
    """The secret values this service was given (each service only gets its own), longest
    first, to blank wherever they turn up in a message."""
    values = [settings.admin_password, settings.public_github_token, settings.hass_token,
              settings.anthropic_api_key, settings.ai_api_key, *settings.git_tokens.values()]
    with contextlib.suppress(ArgumentError):
        values.append(make_url(settings.database_url).password or "")
    for url in re.split(r"[\s,]+", settings.notify_urls):
        # Apprise keeps its secrets in the URL's parts: tgram://<bot token>/<chat>,
        # mailto://user:<password>@host, ntfy://<topic>...
        values += [url, *re.split(r"[/:@?&=#]+", url.partition("://")[2])]
    return sorted({v for v in values if len(v) >= _MIN_SECRET}, key=len, reverse=True)


def redact(text: str, secrets: Iterable[str]) -> str:
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, REDACTED)
    return text


def _cut(text: str) -> str:
    if len(text) <= MESSAGE_MAX:
        return text
    head = MESSAGE_MAX // 5
    return f"{text[:head]}\n…\n{text[-(MESSAGE_MAX - head):]}"


def prune(session: Session, keep_days: int, now: datetime.datetime) -> None:
    session.execute(delete(LogEntry).where(LogEntry.at < now - datetime.timedelta(days=keep_days)))
    newest = session.scalar(select(func.max(LogEntry.id)))
    if newest is not None and newest > KEEP_ROWS:
        session.execute(delete(LogEntry).where(LogEntry.id <= newest - KEEP_ROWS))


class DatabaseHandler(logging.Handler):
    """Queues the messages worth keeping; a background thread writes them."""

    def __init__(self, service: str, secrets: Iterable[str] = (),
                 keep_days: int | None = None) -> None:  # fmt: skip
        super().__init__(logging.INFO)
        self.service = service
        self.secrets = list(secrets)
        self.keep_days = keep_days  # set: this service also clears out old messages
        self.setFormatter(logging.Formatter("%(message)s"))  # and a traceback, if any
        self._queue: queue.Queue = queue.Queue(QUEUE_MAX)
        self._failing = False
        self._thread = threading.Thread(target=self._run, name="scentry-log", daemon=True)
        # Before the handler's lock is taken: whatever the writer itself logs (a database
        # warning) mustn't come back to it.
        self.addFilter(lambda r: threading.current_thread() is not self._thread and wanted(r))
        self._thread.start()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            at = datetime.datetime.fromtimestamp(record.created, datetime.UTC)
            self._queue.put_nowait({
                "at": at.replace(tzinfo=None), "service": self.service,
                "level": record.levelno, "logger": record.name[:100],
                "message": _cut(redact(self.format(record), self.secrets)),
            })  # fmt: skip
        except queue.Full:
            pass
        except Exception:  # noqa: BLE001 - logging's own way of reporting a broken handler
            self.handleError(record)

    def flush(self, timeout: float = 5.0) -> None:
        """Wait (a little) until what was logged so far is written."""
        if not self._thread.is_alive():
            return
        written = threading.Event()
        try:
            self._queue.put(written, timeout=timeout)
        except queue.Full:
            return
        written.wait(timeout)

    def close(self) -> None:
        if self._thread.is_alive():
            try:
                self._queue.put(_STOP, timeout=1)
                self._thread.join(5)
            except queue.Full:
                pass
        super().close()

    def _run(self) -> None:
        next_prune = 0.0
        while True:
            batch, marks, stop = [], [], False
            try:
                item = self._queue.get(timeout=60)
                while True:
                    if item is _STOP:
                        stop = True
                    elif isinstance(item, threading.Event):
                        marks.append(item)
                    else:
                        batch.append(item)
                    if stop or len(batch) >= BATCH:
                        break
                    item = self._queue.get_nowait()
            except queue.Empty:
                pass
            if batch:
                self._write(batch)
            if self.keep_days is not None and time.monotonic() >= next_prune:
                next_prune = time.monotonic() + PRUNE_SECONDS
                self._database(lambda s: prune(s, self.keep_days, utcnow()))
            for mark in marks:
                mark.set()
            if stop:
                return

    def _write(self, batch: list[dict]) -> None:
        self._database(lambda s: s.execute(insert(LogEntry), batch))

    def _database(self, work) -> None:
        try:
            with db.SessionLocal() as session:
                work(session)
                session.commit()
            self._failing = False
        except Exception as exc:  # noqa: BLE001 - the log must never stop a service
            if not self._failing:
                self._failing = True
                problem = redact(f"{type(exc).__name__}: {exc}", self.secrets)[:300]
                print(f"The log can't be kept in the database for now: {problem}",
                      file=sys.stderr)  # fmt: skip


def install(service: str, settings: Settings, *, prune_old: bool = False) -> DatabaseHandler:
    """Keep this service's log in the database too (call after db.configure). The one
    service with `prune_old` clears out old messages."""
    handler = DatabaseHandler(service, secrets_of(settings),
                              settings.log_days if prune_old else None)  # fmt: skip
    logging.getLogger().addHandler(handler)
    ours = logging.getLogger("scentry")
    if ours.getEffectiveLevel() > logging.INFO:
        ours.setLevel(logging.INFO)
    return handler
