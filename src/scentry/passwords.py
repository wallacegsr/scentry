"""The admin's password, once it's set in the portal or with `scentry reset-password`.

Until then the password is SCENTRY_ADMIN_PASSWORD; after, the one in the database is, as
a scrypt hash (its settings are kept in it, so they can be raised later), and the .env
one no longer signs in. Whoever can run a command in a Scentry container can set a new
one: they can read the database and .env anyway. There's no reset by e-mail.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from scentry.models import AdminPassword, utcnow

if TYPE_CHECKING:
    from scentry.config import Settings

MIN_LENGTH = 12
MAX_LENGTH = 1024
# OWASP's scrypt settings with 32 MiB of memory (N=2^15, r=8, p=3): about half a second
# on a desktop, so a guess costs that much each. At most two run at once.
N, R, P = 2**15, 8, 3
_MAXMEM = 128 * 1024 * 1024
_HASHING = threading.BoundedSemaphore(2)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, size: int) -> bytes:
    with _HASHING:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                              maxmem=_MAXMEM, dklen=size)  # fmt: skip


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = _scrypt(password, salt, N, R, P, 32)
    return f"scrypt${N}${R}${P}${_b64(salt)}${_b64(key)}"


def check_password(password: str, stored: str) -> bool:
    try:
        kind, n, r, p, salt, key = stored.split("$")
        if kind != "scrypt":
            return False
        salt_bytes, key_bytes = base64.b64decode(salt), base64.b64decode(key)
        got = _scrypt(password, salt_bytes, int(n), int(r), int(p), len(key_bytes))
    except (ValueError, TypeError):
        return False  # not a hash this code made: nothing matches it
    return hmac.compare_digest(got, key_bytes)


def problem(new: str, repeat: str) -> str | None:
    """What's wrong with a new password, if anything."""
    if new != repeat:
        return "The two new passwords aren't the same."
    if len(new) < MIN_LENGTH:
        return f"Use at least {MIN_LENGTH} characters: a few words is easiest to remember."
    if len(new) > MAX_LENGTH:
        return f"Use at most {MAX_LENGTH} characters."
    if not new.strip():
        return "A password can't be only spaces."
    return None


def stored(session: Session) -> AdminPassword | None:
    return session.get(AdminPassword, 1)


def set_password(session: Session, password: str, by: str) -> None:
    """Set it (the caller commits). `by`: "portal" or "command"."""
    row = stored(session) or AdminPassword(id=1)
    row.hash, row.set_at, row.set_by = hash_password(password), utcnow(), by
    session.add(row)


def forget(session: Session) -> bool:
    """Back to SCENTRY_ADMIN_PASSWORD. False if there was nothing to forget."""
    row = stored(session)
    if row is None:
        return False
    session.delete(row)
    return True


class Verified:
    """The browser sends the password with every request, and scrypt is slow on purpose:
    the last one that matched is remembered, as an HMAC under a key that exists only in
    this process, for as long as the stored hash stays the same."""

    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)
        self._seen: tuple[str, bytes] | None = None

    def check(self, password: str, stored_hash: str) -> bool:
        mac = hmac.new(self._key, password.encode("utf-8"), "sha256").digest()
        seen = self._seen
        if seen is not None and seen[0] == stored_hash and hmac.compare_digest(seen[1], mac):
            return True
        if check_password(password, stored_hash):
            self._seen = (stored_hash, mac)
            return True
        return False


# --- scentry reset-password ------------------------------------------------------------


def reset(settings: Settings | None = None, *, generate: bool = False,
          use_env: bool = False, ask=None, say=print) -> int:
    """The command: a new password typed twice (or made up and shown once, or back to
    SCENTRY_ADMIN_PASSWORD), written to the database the portal reads. Run it in the web
    container, which has the database's address. Returns the exit status."""
    import getpass
    import logging

    from scentry import db
    from scentry.config import get_settings
    from scentry.models import LogEntry

    ask = ask or getpass.getpass
    settings = settings or get_settings()
    db.configure(settings.database_url)
    if settings.auth_mode != "basic":
        say(f"Note: SCENTRY_AUTH_MODE is {settings.auth_mode}, so the portal doesn't ask for "
            "this password.")  # fmt: skip
    with db.SessionLocal() as session:
        if use_env:
            if not settings.admin_password:
                say("SCENTRY_ADMIN_PASSWORD isn't set here, so nothing would sign in. "
                    "Nothing changed.")  # fmt: skip
                return 1
            if not forget(session):
                say("No password was set in the portal: SCENTRY_ADMIN_PASSWORD already signs in.")
                return 0
            what = "set back to SCENTRY_ADMIN_PASSWORD"
        else:
            if generate:
                new = secrets.token_urlsafe(18)  # 24 characters, 144 bits
            else:
                try:
                    new, repeat = ask("New password: "), ask("The new password again: ")
                except EOFError:
                    say("Nothing to read the password from: run it with docker exec -it, or "
                        "use --generate.")  # fmt: skip
                    return 1
                if wrong := problem(new, repeat):
                    say(f"{wrong} Nothing changed.")
                    return 1
            set_password(session, new, "command")
            what = "reset with scentry reset-password"
        session.add(LogEntry(at=utcnow(), service="web", level=logging.INFO,
                             logger="scentry.passwords",
                             message=f"The admin password was {what}."))  # fmt: skip
        session.commit()
    if generate:
        say(f"The new password, shown this once: {new}")
    say(f"The admin password was {what}. Browsers signed in with the old one ask again.")
    return 0
