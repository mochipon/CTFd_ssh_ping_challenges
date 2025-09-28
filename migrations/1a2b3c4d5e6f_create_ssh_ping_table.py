"""Create table for SSH-based ping challenges.

This migration creates the ssh_ping_challenge table with all necessary
columns for storing bastion configuration and ping command templates.

Revision ID: 1a2b3c4d5e6f
Revises:
Create Date: 2024-05-06 00:00:00.000000

"""

import sqlalchemy as sa

# Revision identifiers
revision = "1a2b3c4d5e6f"
down_revision = None
branch_labels = None
depends_on = None


def upgrade(op=None) -> None:
    """Create the ssh_ping_challenge table with all required columns."""
    op.create_table(
        "ssh_ping_challenge",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "bastion_host_template",
            sa.Text(),
            nullable=False,
            server_default="",
        ),
        sa.Column(
            "bastion_username_template",
            sa.Text(),
            nullable=False,
            server_default="",
        ),
        sa.Column(
            "bastion_password_template",
            sa.Text(),
            nullable=False,
            server_default="",
        ),
        sa.Column(
            "bastion_enable_password_template",
            sa.Text(),
            nullable=False,
            server_default="",
        ),
        sa.Column(
            "bastion_display_name_template",
            sa.Text(),
            nullable=False,
            server_default="",
        ),
        sa.Column(
            "per_pod_bastion_overrides",
            sa.Text(),
            nullable=False,
            server_default="",
        ),
        sa.Column(
            "ping_command_template",
            sa.Text(),
            nullable=False,
            server_default="ping {target} repeat 1 timeout 2",
        ),
        sa.Column(
            "ssh_timeout",
            sa.Integer(),
            nullable=False,
            server_default="10",
        ),
        sa.ForeignKeyConstraint(
            ["id"],
            ["challenges.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade(op=None) -> None:
    """Drop the ssh_ping_challenge table."""
    op.drop_table("ssh_ping_challenge")
