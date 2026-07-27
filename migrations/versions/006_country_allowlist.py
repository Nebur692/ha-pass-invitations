"""Country allowlist for guest tokens (replaces the raw-CIDR "IP allowlist" field).

Adds `country_allowlist` (nullable JSON array of ISO 3166-1 alpha-2 codes,
e.g. `["ES", "PT"]`) — the country/countries an admin picks in the create
token form for the whole-link access check. This is purely for display/edit
purposes: at creation time the app resolves the chosen countries into their
known public IP ranges (via app/geoip.py) and stores those resolved CIDRs in
the existing `ip_allowlist` column, which `app/routers/guest.py` already
enforces unchanged. `country_allowlist` just remembers what the admin
actually picked, so the dashboard can show "Spain, Portugal" instead of a
few thousand raw CIDR blocks.

Distinct from `LOCAL_NETWORK_CIDRS` (an add-on-level *fixed* setting, not
per-token, that gates command *execution* on lock/cover/button entities —
see app/routers/guest.py `_enforce_local_network_for_domain`). That one is
unchanged; this migration only touches the optional per-token allowlist.

Revision ID: 006
Revises: 005
Create Date: 2026-07-28
"""
from typing import Sequence, Union

from alembic import op

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE tokens ADD COLUMN country_allowlist TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE tokens DROP COLUMN country_allowlist")
