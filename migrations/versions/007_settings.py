"""Runtime settings, so deployment options stop requiring a container restart.

Until now every option lived only in an environment variable. That works for
Home Assistant add-on installs, where the Supervisor renders a configuration
form from config.yaml — but there is no such form for a standalone Docker
install, which is how the Unraid template deploys this. Those users had no
configuration UI at all: edit the container template, restart, repeat. Finding
a Bluetooth door scanner made that painfully obvious, because the value you
need is discovered by the admin panel itself.

This table holds admin-edited overrides. Precedence is: environment variable
seeds the value, a row here wins once the admin changes it (see
app/settings_store.py). Credentials and bootstrap options — HA_BASE_URL,
HA_TOKEN, DB_PATH, PORT, ADMIN_* — deliberately stay environment-only: the app
cannot read its own database to find out where its database is.

Values are stored as JSON so lists and integers survive the round trip.

Revision ID: 007
Revises: 006
Create Date: 2026-08-01
"""
from typing import Sequence, Union

from alembic import op

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE settings (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE settings")
