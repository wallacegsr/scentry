"""Suppress a scanner rule in the files that match a pattern

Revision ID: 0012
Revises: 0011
Created: 2026-11-19 23:30:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'rule_suppressions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('scanner', sa.String(length=50), nullable=False),
        sa.Column('rule_id', sa.String(length=300), nullable=False),
        sa.Column('pattern', sa.String(length=500), nullable=False),
        sa.Column('reason', sa.String(length=50), nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('created_by', sa.String(length=200), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('until', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('rule_suppressions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_rule_suppressions_target_id'), ['target_id'],
                              unique=False)
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('rule_suppression_id', sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_column('rule_suppression_id')
    with op.batch_alter_table('rule_suppressions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_rule_suppressions_target_id'))
    op.drop_table('rule_suppressions')
