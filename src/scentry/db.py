from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from scentry.models import Base

SessionLocal: sessionmaker[Session] = sessionmaker(expire_on_commit=False)


def configure(database_url: str) -> None:
    """Bind the session factory and create missing tables."""
    kwargs = {}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(database_url, pool_pre_ping=True, **kwargs)
    Base.metadata.create_all(engine)
    SessionLocal.configure(bind=engine)


def get_session() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session
