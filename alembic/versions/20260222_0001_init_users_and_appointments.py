"""Initialize users and appointments schema.

Revision ID: 20260222_0001
Revises:
Create Date: 2026-02-22 22:20:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260222_0001"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _column_names(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {col["name"] for col in inspector.get_columns(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "users" not in table_names:
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("email", sa.String(), nullable=False),
            sa.Column("password", sa.String(), nullable=False),
            sa.Column("role", sa.String(), nullable=False, server_default="client"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_users_email", "users", ["email"], unique=True)
        op.create_index("ix_users_id", "users", ["id"], unique=False)
    else:
        user_columns = _column_names("users")
        if "role" not in user_columns:
            op.add_column("users", sa.Column("role", sa.String(), nullable=True))
            op.execute("UPDATE users SET role = 'client' WHERE role IS NULL")
            with op.batch_alter_table("users") as batch_op:
                batch_op.alter_column("role", existing_type=sa.String(), nullable=False)

    if "appointments" not in table_names:
        op.create_table(
            "appointments",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("user_email", sa.String(), nullable=False),
            sa.Column("date", sa.String(), nullable=False),
            sa.Column("time", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_appointments_id", "appointments", ["id"], unique=False)
        op.create_index("ix_appointments_user_email", "appointments", ["user_email"], unique=False)
        op.create_index("ix_appointments_user_id", "appointments", ["user_id"], unique=False)
    else:
        appt_columns = _column_names("appointments")
        if "user_id" not in appt_columns:
            op.add_column("appointments", sa.Column("user_id", sa.Integer(), nullable=True))
            op.create_index("ix_appointments_user_id", "appointments", ["user_id"], unique=False)


def downgrade() -> None:
    # This migration is intentionally conservative because it can run against
    # legacy databases with varying schemas.
    pass
