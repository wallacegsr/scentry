"""ai providers

Revision ID: 0008
Revises: 0007
Created: 2026-11-18 07:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('ai_state', schema=None) as batch_op:
        batch_op.add_column(sa.Column('provider', sa.String(length=20), nullable=True))
    # Until now Claude was the only one.
    op.execute("UPDATE ai_state SET provider = 'anthropic' WHERE configured")


def downgrade() -> None:
    with op.batch_alter_table('ai_state', schema=None) as batch_op:
        batch_op.drop_column('provider')
