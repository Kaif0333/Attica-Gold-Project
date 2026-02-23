"""Add inquiry management fields for assignment and resolution notes.

Revision ID: 20260224_0006
Revises: 20260223_0005
Create Date: 2026-02-24 00:20:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260224_0006"
down_revision: Union[str, Sequence[str], None] = "20260223_0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _column_names(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {col["name"] for col in inspector.get_columns(table_name)}


def _index_names(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {idx["name"] for idx in inspector.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())
    if "inquiries" not in table_names:
        return

    columns = _column_names("inquiries")
    if "assigned_to_email" not in columns:
        op.add_column("inquiries", sa.Column("assigned_to_email", sa.String(), nullable=True))
    if "admin_note" not in columns:
        op.add_column("inquiries", sa.Column("admin_note", sa.String(), nullable=True))
    if "updated_at" not in columns:
        op.add_column("inquiries", sa.Column("updated_at", sa.DateTime(), nullable=True))
        op.execute("UPDATE inquiries SET updated_at = created_at WHERE updated_at IS NULL")

    indexes = _index_names("inquiries")
    if "ix_inquiries_updated_at" not in indexes:
        op.create_index("ix_inquiries_updated_at", "inquiries", ["updated_at"], unique=False)


def downgrade() -> None:
    pass
