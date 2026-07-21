"""Scheduled/recurring access, local-network-only commands, and single-browser binding.

Adds nullable columns to `tokens` for:
  - advance scheduling (`starts_at`) and recurring weekly windows (`recurrence`)
  - automatic invite delivery via an HA notify service (`notify_service`,
    `notify_lead_seconds`, `notify_sent`)
  - single-browser binding so a link can't be forwarded and used from a
    second device (`bound_secret`, `bound_claimed_at`)

All columns are nullable and default to NULL, which preserves the exact
current behavior for existing tokens (no schedule = active immediately,
no notify = no automatic send, unbound = first browser to open it claims it).

Revision ID: 003
Revises: 002
Create Date: 2026-07-22
"""
from typing import Sequence, Union

from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Plain ADD COLUMN is safe here (unlike 002): no FK/constraint change,
    # just new nullable columns, which SQLite supports natively.
    op.execute("ALTER TABLE tokens ADD COLUMN starts_at INTEGER")
    op.execute("ALTER TABLE tokens ADD COLUMN recurrence TEXT")
    op.execute("ALTER TABLE tokens ADD COLUMN notify_service TEXT")
    op.execute("ALTER TABLE tokens ADD COLUMN notify_lead_seconds INTEGER")
    op.execute("ALTER TABLE tokens ADD COLUMN notify_sent INTEGER NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE tokens ADD COLUMN bound_secret TEXT")
    op.execute("ALTER TABLE tokens ADD COLUMN bound_claimed_at INTEGER")
    op.execute("CREATE INDEX IF NOT EXISTS idx_tokens_starts_at ON tokens(starts_at)")


def downgrade() -> None:
    # SQLite can't DROP COLUMN pre-3.35 reliably via Alembic's sqlite dialect;
    # rebuild the table back to the 002 shape, matching that migration's style.
    op.execute("ALTER TABLE tokens RENAME TO _tokens_old")
    op.execute("""
        CREATE TABLE tokens (
            id              TEXT PRIMARY KEY,
            slug            TEXT UNIQUE NOT NULL,
            label           TEXT NOT NULL,
            created_at      INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            revoked         INTEGER NOT NULL DEFAULT 0,
            last_accessed   INTEGER,
            rate_limit_rpm  INTEGER NOT NULL DEFAULT 30,
            ip_allowlist    TEXT
        )
    """)
    op.execute("""
        INSERT INTO tokens (id, slug, label, created_at, expires_at, revoked,
                            last_accessed, rate_limit_rpm, ip_allowlist)
        SELECT id, slug, label, created_at, expires_at, revoked,
               last_accessed, rate_limit_rpm, ip_allowlist
        FROM _tokens_old
    """)
    op.execute("DROP TABLE _tokens_old")
    op.execute("CREATE INDEX IF NOT EXISTS idx_tokens_slug ON tokens(slug)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at)")
