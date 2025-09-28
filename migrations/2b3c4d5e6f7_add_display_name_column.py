"""Add display name template column.

This migration adds the bastion_display_name_template column to existing
ssh_ping_challenge tables if it doesn't already exist. This supports
backwards compatibility with existing installations.

Revision ID: 2b3c4d5e6f7
Revises: 1a2b3c4d5e6f
Create Date: 2024-05-06 00:00:00.000001

"""

import sqlalchemy as sa

from CTFd.plugins.migrations import get_columns_for_table

# Revision identifiers
revision = "2b3c4d5e6f7"
down_revision = "1a2b3c4d5e6f"
branch_labels = None
depends_on = None


def upgrade(op=None) -> None:
    """Add bastion_display_name_template column if it doesn't exist."""
    columns = get_columns_for_table(op, "ssh_ping_challenge", names_only=True)
    if "bastion_display_name_template" not in columns:
        op.add_column(
            "ssh_ping_challenge",
            sa.Column(
                "bastion_display_name_template",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
        )


def downgrade(op=None) -> None:
    """Remove the bastion_display_name_template column."""
    columns = get_columns_for_table(op, "ssh_ping_challenge", names_only=True)
    if "bastion_display_name_template" in columns:
        op.drop_column("ssh_ping_challenge", "bastion_display_name_template")
