"""Barkley's plain words on scans, and rule details on findings

Revision ID: 0010
Revises: 0009
Created: 2026-11-18 21:20:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('plain', sa.JSON(), nullable=True))
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('details', sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_column('details')
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_column('plain')
