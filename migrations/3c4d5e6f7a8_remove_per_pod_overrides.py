"""Remove per_pod_bastion_overrides column to simplify configuration.

This migration removes the per_pod_bastion_overrides column as part of
code simplification efforts. The functionality is replaced with simpler
template-based configuration using pod token substitution.

Revision ID: 3c4d5e6f7a8
Revises: 2b3c4d5e6f7
Create Date: 2025-09-28 12:00:00.000000

"""

import sqlalchemy as sa

from CTFd.plugins.migrations import get_columns_for_table

# Revision identifiers
revision = "3c4d5e6f7a8"
down_revision = "2b3c4d5e6f7"
branch_labels = None
depends_on = None


def upgrade(op=None) -> None:
    """Remove the per_pod_bastion_overrides column."""
    columns = get_columns_for_table(op, "ssh_ping_challenge", names_only=True)
    if "per_pod_bastion_overrides" in columns:
        op.drop_column("ssh_ping_challenge", "per_pod_bastion_overrides")


def downgrade(op=None) -> None:
    """Re-add the per_pod_bastion_overrides column."""
    columns = get_columns_for_table(op, "ssh_ping_challenge", names_only=True)
    if "per_pod_bastion_overrides" not in columns:
        op.add_column(
            "ssh_ping_challenge",
            sa.Column(
                "per_pod_bastion_overrides",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
        )
