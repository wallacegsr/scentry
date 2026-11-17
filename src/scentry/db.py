from __future__ import annotations

import tempfile
from collections.abc import Iterator
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

SessionLocal: sessionmaker[Session] = sessionmaker(expire_on_commit=False)

# The schema as it was when tables were still created at start (before migrations):
# a database made that way is adopted at this revision.
BASELINE = "0001"
# Postgres advisory lock held while migrating, so the services starting together
# migrate one at a time (the first does the work, the others find nothing to do).
MIGRATION_LOCK = 0x5C3E7_0001


def _config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", "scentry:migrations")
    return cfg


def make_engine(database_url: str) -> Engine:
    kwargs = {}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(database_url, pool_pre_ping=True, **kwargs)


def migrate(engine: Engine) -> None:
    """Bring the database to the newest schema. Safe to run from every service at once."""
    cfg = _config()
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK})
        cfg.attributes["connection"] = conn
        tables = set(inspect(conn).get_table_names())
        if "alembic_version" not in tables and "targets" in tables:
            command.stamp(cfg, BASELINE)  # made by create_all before migrations existed
        command.upgrade(cfg, "head")


def configure(database_url: str) -> None:
    """Bind the session factory, migrating the database first."""
    engine = make_engine(database_url)
    migrate(engine)
    SessionLocal.configure(bind=engine)


def new_revision(message: str) -> list[str]:
    """Write a migration for what the models have that the newest migration lacks, by
    comparing them with a scratch SQLite database at head. Review it before committing:
    autogenerate misses renames and some type changes."""
    with tempfile.TemporaryDirectory() as tmp:
        engine = make_engine(f"sqlite:///{Path(tmp) / 'head.db'}")
        migrate(engine)
        cfg = _config()
        number = len(list(ScriptDirectory.from_config(cfg).walk_revisions())) + 1
        with engine.begin() as conn:
            cfg.attributes["connection"] = conn
            scripts = command.revision(cfg, message=message, autogenerate=True,
                                       rev_id=f"{number:04d}")  # fmt: skip
        engine.dispose()
    scripts = scripts if isinstance(scripts, list) else [scripts]
    return [s.path for s in scripts if s is not None]


def get_session() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session
