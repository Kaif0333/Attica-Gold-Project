"""Add password reset columns to users.

Revision ID: 20260222_0002
Revises: 20260222_0001
Create Date: 2026-02-22 23:10:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260222_0002"
down_revision: Union[str, Sequence[str], None] = "20260222_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _user_columns() -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {col["name"] for col in inspector.get_columns("users")}


def upgrade() -> None:
    columns = _user_columns()
    if "reset_token_hash" not in columns:
        op.add_column("users", sa.Column("reset_token_hash", sa.String(), nullable=True))
    if "reset_token_expires_at" not in columns:
        op.add_column("users", sa.Column("reset_token_expires_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    columns = _user_columns()
    with op.batch_alter_table("users") as batch_op:
        if "reset_token_expires_at" in columns:
            batch_op.drop_column("reset_token_expires_at")
        if "reset_token_hash" in columns:
            batch_op.drop_column("reset_token_hash")
