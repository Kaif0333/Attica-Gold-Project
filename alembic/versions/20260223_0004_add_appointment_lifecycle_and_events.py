"""Add appointment lifecycle fields and appointment events timeline.

Revision ID: 20260223_0004
Revises: 20260222_0003
Create Date: 2026-02-23 22:30:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260223_0004"
down_revision: Union[str, Sequence[str], None] = "20260222_0003"
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

    if "appointments" in table_names:
        appt_columns = _column_names("appointments")
        if "status" not in appt_columns:
            op.add_column("appointments", sa.Column("status", sa.String(), nullable=True))
            op.execute("UPDATE appointments SET status = 'scheduled' WHERE status IS NULL")
            with op.batch_alter_table("appointments") as batch_op:
                batch_op.alter_column("status", existing_type=sa.String(), nullable=False)
        if "updated_at" not in appt_columns:
            op.add_column("appointments", sa.Column("updated_at", sa.DateTime(), nullable=True))
            op.execute("UPDATE appointments SET updated_at = created_at WHERE updated_at IS NULL")

    if "appointment_events" not in table_names:
        op.create_table(
            "appointment_events",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("appointment_id", sa.Integer(), nullable=False),
            sa.Column("action", sa.String(), nullable=False),
            sa.Column("actor_id", sa.Integer(), nullable=True),
            sa.Column("actor_email", sa.String(), nullable=True),
            sa.Column("actor_role", sa.String(), nullable=True),
            sa.Column("note", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_appointment_events_id", "appointment_events", ["id"], unique=False)
        op.create_index(
            "ix_appointment_events_appointment_id",
            "appointment_events",
            ["appointment_id"],
            unique=False,
        )
        op.create_index("ix_appointment_events_action", "appointment_events", ["action"], unique=False)
        op.create_index(
            "ix_appointment_events_actor_id",
            "appointment_events",
            ["actor_id"],
            unique=False,
        )
        op.create_index(
            "ix_appointment_events_actor_email",
            "appointment_events",
            ["actor_email"],
            unique=False,
        )
        op.create_index(
            "ix_appointment_events_created_at",
            "appointment_events",
            ["created_at"],
            unique=False,
        )
    else:
        event_indexes = _index_names("appointment_events")
        expected_indexes = {
            "ix_appointment_events_appointment_id": ["appointment_id"],
            "ix_appointment_events_action": ["action"],
            "ix_appointment_events_actor_id": ["actor_id"],
            "ix_appointment_events_actor_email": ["actor_email"],
            "ix_appointment_events_created_at": ["created_at"],
        }
        for idx_name, columns in expected_indexes.items():
            if idx_name not in event_indexes:
                op.create_index(idx_name, "appointment_events", columns, unique=False)


def downgrade() -> None:
    # Kept conservative because this migration may run against mixed historical schemas.
    pass
