"""Migrations: a fresh database, one made by create_all before migrations existed, and
the models never drifting from what the migrations build.

Runs on SQLite, and on Postgres too when SCENTRY_TEST_POSTGRES is a URL to an empty
scratch database (CI sets it): `postgresql+psycopg://user:pw@host/db`.
"""

from __future__ import annotations

import os
import threading

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

from scentry import db
from scentry.models import Base, Target

POSTGRES = os.environ.get("SCENTRY_TEST_POSTGRES")
BACKENDS = ["sqlite"] + (["postgres"] if POSTGRES else [])


@pytest.fixture(params=BACKENDS)
def engine(request, tmp_path):
    if request.param == "sqlite":
        engine = db.make_engine(f"sqlite:///{tmp_path / 'm.db'}")
    else:
        engine = db.make_engine(POSTGRES)
        with engine.begin() as conn:  # start from nothing
            conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
    yield engine
    engine.dispose()


def _head() -> str:
    return ScriptDirectory.from_config(db._config()).get_current_head()


def _version(engine) -> str | None:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def _drift(engine) -> list:
    with engine.connect() as conn:
        return compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}),
                                Base.metadata)  # fmt: skip


def test_fresh_database_matches_the_models(engine):
    db.migrate(engine)
    assert _version(engine) == _head()
    assert _drift(engine) == []  # a model change without a migration fails here
    db.migrate(engine)  # nothing to do the second time
    assert _version(engine) == _head()


def test_database_from_before_migrations_is_adopted(engine):
    from sqlalchemy.orm import Session

    Base.metadata.create_all(engine)  # how every database was made up to 131364f
    with Session(engine) as s:
        s.add(Target(name="kept", profile="ha", source="a/b"))
        s.commit()
    db.migrate(engine)
    assert _version(engine) == _head()
    assert _drift(engine) == []
    with Session(engine) as s:
        assert s.query(Target).one().name == "kept"


def test_services_starting_together_migrate_once(engine):
    if engine.dialect.name != "postgresql":
        pytest.skip("the lock is Postgres's; SQLite is for one process")
    errors = []

    def start():
        try:
            db.migrate(engine)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=start) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert _version(engine) == _head()
    assert "targets" in inspect(engine).get_table_names()
