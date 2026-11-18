"""the services' log

Revision ID: 0009
Revises: 0008
Created: 2026-11-18 08:40:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'log_entries',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('at', sa.DateTime(), nullable=False),
        sa.Column('service', sa.String(length=20), nullable=False),
        sa.Column('level', sa.Integer(), nullable=False),
        sa.Column('logger', sa.String(length=100), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('log_entries', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_log_entries_at'), ['at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('log_entries', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_log_entries_at'))
    op.drop_table('log_entries')
