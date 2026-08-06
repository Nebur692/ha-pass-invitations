"""Remember which device claimed a guest link.

The panel could only say "paired 8h ago", which does not answer the question an
admin actually has when a guest reports being locked out: *whose* device is
holding the link. Telling apart "my guest paired it" from "I claimed it myself
while testing" meant reading the database by hand.

Backfilled from the access log, because the answer for existing links is
already there — the visit that claimed a link was recorded at the same second
as `bound_claimed_at`. A one-second window is enough to match it and narrow
enough not to attach an unrelated visit.

Revision ID: 008
Revises: 007
Create Date: 2026-08-07
"""
from typing import Sequence, Union

from alembic import op

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE tokens ADD COLUMN bound_user_agent TEXT")
    op.execute(
        """
        UPDATE tokens
           SET bound_user_agent = (
               SELECT a.user_agent
                 FROM access_log a
                WHERE a.token_id = tokens.id
                  AND a.user_agent IS NOT NULL
                  AND a.timestamp BETWEEN tokens.bound_claimed_at - 1
                                      AND tokens.bound_claimed_at + 1
                ORDER BY a.timestamp DESC
                LIMIT 1
           )
         WHERE bound_claimed_at IS NOT NULL
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE tokens DROP COLUMN bound_user_agent")
