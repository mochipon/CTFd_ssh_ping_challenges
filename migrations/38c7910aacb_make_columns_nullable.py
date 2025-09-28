"""Make ping_command_template and ssh_timeout columns nullable.

Revision ID: 38c7910aacb
Revises: 3c4d5e6f7a8
Create Date: 2024-01-01 00:00:00.000000

"""

import sqlalchemy as sa

from CTFd.plugins.migrations import get_columns_for_table

# revision identifiers, used by Alembic.
revision = "38c7910aacb"
down_revision = "3c4d5e6f7a8"
branch_labels = None
depends_on = None


def upgrade(op=None) -> None:
    """Make columns nullable to allow runtime default application."""
    columns = get_columns_for_table(op, "ssh_ping_challenge", names_only=True)
    if "ping_command_template" in columns:
        op.alter_column(
            "ssh_ping_challenge",
            "ping_command_template",
            existing_type=sa.Text(),
            nullable=True,
            existing_nullable=False,
            server_default=None,
            existing_server_default="ping {target} repeat 1 timeout 2",
        )

    if "ssh_timeout" in columns:
        op.alter_column(
            "ssh_ping_challenge",
            "ssh_timeout",
            existing_type=sa.Integer(),
            nullable=True,
            existing_nullable=False,
            server_default=None,
            existing_server_default="10",
        )


def downgrade(op=None) -> None:
    """Restore NOT NULL constraints."""
    columns = get_columns_for_table(op, "ssh_ping_challenge", names_only=True)
    if "ping_command_template" in columns:
        op.alter_column(
            "ssh_ping_challenge",
            "ping_command_template",
            existing_type=sa.Text(),
            nullable=False,
            existing_nullable=True,
            server_default="ping {target} repeat 1 timeout 2",
            existing_server_default=None,
        )

    if "ssh_timeout" in columns:
        op.alter_column(
            "ssh_ping_challenge",
            "ssh_timeout",
            existing_type=sa.Integer(),
            nullable=False,
            existing_nullable=True,
            server_default="10",
            existing_server_default=None,
        )
