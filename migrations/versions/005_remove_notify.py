"""Remove the automatic notify.* delivery feature.

Dropped `notify_service`, `notify_lead_seconds`, `notify_sent`. This feature
was never actually wired to a scheduler — `db.list_tokens_pending_notify()`
existed but nothing ever called it, so no notification was ever sent in
practice. Removed after review: guests aren't Home Assistant users, so
`notify.*` (which targets HA-registered devices/services) never made sense
as a way to reach *them* directly; at best it could nudge a household
member's own phone, which isn't what the feature was framed as. Simpler to
drop it than keep dead code around.

Revision ID: 005
Revises: 004
Create Date: 2026-07-28
"""
from typing import Sequence, Union

from alembic import op

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLite 3.35+ supports DROP COLUMN natively — no rebuild-table dance needed.
    op.execute("ALTER TABLE tokens DROP COLUMN notify_service")
    op.execute("ALTER TABLE tokens DROP COLUMN notify_lead_seconds")
    op.execute("ALTER TABLE tokens DROP COLUMN notify_sent")


def downgrade() -> None:
    op.execute("ALTER TABLE tokens ADD COLUMN notify_service TEXT")
    op.execute("ALTER TABLE tokens ADD COLUMN notify_lead_seconds INTEGER")
    op.execute("ALTER TABLE tokens ADD COLUMN notify_sent INTEGER NOT NULL DEFAULT 0")
