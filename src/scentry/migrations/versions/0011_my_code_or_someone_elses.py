"""A repository is my code, or someone else's

Revision ID: 0011
Revises: 0010
Created: 2026-11-19 22:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('targets', schema=None) as batch_op:
        # Every repository so far was listed as "My code": it stays there until moved.
        # sa.true(), not sa.text('1'): Postgres won't take 1 for a boolean.
        batch_op.add_column(sa.Column('mine', sa.Boolean(), server_default=sa.true(),
                                      nullable=False))


def downgrade() -> None:
    with op.batch_alter_table('targets', schema=None) as batch_op:
        batch_op.drop_column('mine')
