"""Admin-editable settings, layered on top of the environment.

Every option used to live only in an environment variable. That is fine for a
Home Assistant add-on, where the Supervisor renders a configuration form from
config.yaml, but a standalone Docker install gets no such form — and standalone
is how the Unraid template deploys this. Those users had to edit the container
template and restart for every change, which is absurd for something like the
Bluetooth door scanner, whose value the admin panel discovers itself.

Precedence: the environment seeds a setting, and a row in the `settings` table
wins once an admin edits it. Both stay meaningful — an add-on user can keep
configuring from the Supervisor, and nothing silently fights them, because the
panel shows which values have been overridden.

Overrides are applied onto the live `settings` object at startup and on every
change, so the rest of the app keeps reading `settings.app_name` and neither
knows nor cares where the value came from.

Credentials and bootstrap options are deliberately absent from EDITABLE:
`HA_BASE_URL`, `HA_TOKEN`, `DB_PATH`, `PORT`, `ADMIN_USERNAME`,
`ADMIN_PASSWORD`. The app cannot read its own database to discover where its
database is, and an admin locked out by a bad value would have no way back in.
"""
import json
import logging
import time

from app import database as db
from app.config import Settings, settings

logger = logging.getLogger(__name__)

# Settings an admin may change from the panel. Everything else is bootstrap.
EDITABLE: tuple[str, ...] = (
    "app_name",
    "contact_message",
    "brand_bg",
    "brand_primary",
    "guest_url",
    "timezone",
    "access_log_retention_days",
    "local_network_cidrs",
    "presence_modes",
    "presence_policy",
    "ble_scanners",
    "ble_min_rssi",
    "ble_max_age_seconds",
)

# Changing these cannot take effect on the next request alone: whether we
# subscribe to Bluetooth advertisements is decided when the Home Assistant
# WebSocket connects, so the listener has to be brought back up.
NEEDS_WS_RESTART: frozenset[str] = frozenset({"presence_modes"})

# What the process started with, before any override was applied. Kept so the
# panel can show what reverting would restore, and so seeding can tell an
# explicitly-set environment variable from an untouched default.
_env_values: dict[str, object] = {}
_overridden: set[str] = set()


def _defaults() -> dict[str, object]:
    """Field defaults as declared in Settings, ignoring the environment."""
    return {
        name: field.get_default(call_default_factory=True)
        for name, field in Settings.model_fields.items()
        if name in EDITABLE
    }


async def load() -> None:
    """Apply stored overrides onto the live settings object. Call at startup."""
    global _env_values, _overridden
    _env_values = {name: getattr(settings, name) for name in EDITABLE}
    _overridden = set()

    for key, value in (await db.get_settings()).items():
        if key not in EDITABLE:
            logger.warning("Ignoring unknown stored setting %r", key)
            continue
        setattr(settings, key, value)
        _overridden.add(key)

    if _overridden:
        logger.info("Applied %d stored setting(s): %s",
                    len(_overridden), ", ".join(sorted(_overridden)))


async def seed_from_environment() -> None:
    """Persist environment values that differ from the code defaults.

    Run once on upgrade so an existing deployment can drop its environment
    variables without silently reverting to defaults — the values it was
    already running with become stored settings. Only genuinely customised
    ones are stored, so the panel does not open showing a dozen "overridden"
    badges for settings nobody ever touched.
    """
    if await db.get_settings():
        return  # already seeded, or the admin has edited something
    defaults = _defaults()
    customised = {
        name: value for name, value in _env_values.items()
        if value != defaults.get(name)
    }
    if not customised:
        return
    for name, value in customised.items():
        await db.set_setting(name, value, int(time.time()))
        _overridden.add(name)
    logger.info("Seeded %d setting(s) from the environment: %s",
                len(customised), ", ".join(sorted(customised)))


async def apply(changes: dict[str, object]) -> bool:
    """Persist and apply changes. Returns whether the HA listener must restart."""
    now = int(time.time())
    for key, value in changes.items():
        if key not in EDITABLE:
            raise ValueError(f"{key} is not an editable setting")
        await db.set_setting(key, value, now)
        setattr(settings, key, value)
        _overridden.add(key)
    return bool(NEEDS_WS_RESTART & set(changes))


async def reset(key: str) -> bool:
    """Drop an override, falling back to whatever the environment provided."""
    if key not in EDITABLE:
        raise ValueError(f"{key} is not an editable setting")
    await db.delete_setting(key)
    setattr(settings, key, _env_values[key])
    _overridden.discard(key)
    return key in NEEDS_WS_RESTART


def current() -> dict[str, dict]:
    """Every editable setting: live value, environment value, overridden flag."""
    return {
        name: {
            "value": getattr(settings, name),
            "from_environment": _env_values.get(name),
            "overridden": name in _overridden,
        }
        for name in EDITABLE
    }


def reset_state() -> None:
    """For tests: forget what was loaded without touching the database."""
    global _env_values, _overridden
    _env_values = {}
    _overridden = set()
