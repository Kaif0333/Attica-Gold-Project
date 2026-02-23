"""Add inquiries table for contact lead capture.

Revision ID: 20260223_0005
Revises: 20260223_0004
Create Date: 2026-02-23 23:50:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260223_0005"
down_revision: Union[str, Sequence[str], None] = "20260223_0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _index_names(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {idx["name"] for idx in inspector.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "inquiries" not in table_names:
        op.create_table(
            "inquiries",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("email", sa.String(), nullable=False),
            sa.Column("phone", sa.String(), nullable=True),
            sa.Column("city", sa.String(), nullable=True),
            sa.Column("service", sa.String(), nullable=True),
            sa.Column("message", sa.String(), nullable=False),
            sa.Column("status", sa.String(), nullable=False, server_default="new"),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_inquiries_id", "inquiries", ["id"], unique=False)
        op.create_index("ix_inquiries_email", "inquiries", ["email"], unique=False)
        op.create_index("ix_inquiries_created_at", "inquiries", ["created_at"], unique=False)
    else:
        indexes = _index_names("inquiries")
        if "ix_inquiries_email" not in indexes:
            op.create_index("ix_inquiries_email", "inquiries", ["email"], unique=False)
        if "ix_inquiries_created_at" not in indexes:
            op.create_index("ix_inquiries_created_at", "inquiries", ["created_at"], unique=False)


def downgrade() -> None:
    pass
