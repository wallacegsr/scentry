"""Alembic environment. Run only through scentry.db.migrate(), which passes the
connection (already holding the migration lock) in the config's attributes."""

from __future__ import annotations

from alembic import context

from scentry.models import Base

connection = context.config.attributes["connection"]
context.configure(
    connection=connection,
    target_metadata=Base.metadata,
    render_as_batch=True,  # SQLite can't ALTER most things; batch mode copies the table
    compare_type=True,
)
with context.begin_transaction():
    context.run_migrations()
