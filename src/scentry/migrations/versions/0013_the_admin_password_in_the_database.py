"""The admin's password in the database, once it's changed in the portal

Revision ID: 0013
Revises: 0012
Created: 2026-11-22 10:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'admin_password',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('hash', sa.String(length=300), nullable=False),
        sa.Column('set_at', sa.DateTime(), nullable=False),
        sa.Column('set_by', sa.String(length=20), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('admin_password')
