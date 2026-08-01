"""Admin-editable settings layered over the environment.

The reason this exists: only Home Assistant add-on installs get a configuration
form, rendered by the Supervisor. A standalone Docker install — how the Unraid
template deploys this — had none, so every change meant editing the container
and restarting. These tests pin the precedence rule that makes both work.
"""
import pytest

from app import database as db
from app import settings_store
from app.config import settings


@pytest.fixture(autouse=True)
async def _clean_store(test_db):
    settings_store.reset_state()
    original = {name: getattr(settings, name) for name in settings_store.EDITABLE}
    yield
    for name, value in original.items():
        setattr(settings, name, value)
    settings_store.reset_state()


# ---------------------------------------------------------------------------
# Precedence
# ---------------------------------------------------------------------------

async def test_environment_applies_when_nothing_is_stored():
    settings.app_name = "From the container"
    await settings_store.load()

    assert settings.app_name == "From the container"
    assert settings_store.current()["app_name"]["overridden"] is False


async def test_a_stored_value_wins_over_the_environment():
    settings.app_name = "From the container"
    await settings_store.load()

    await settings_store.apply({"app_name": "From the panel"})

    assert settings.app_name == "From the panel"
    entry = settings_store.current()["app_name"]
    assert entry["overridden"] is True
    assert entry["from_environment"] == "From the container"


async def test_stored_values_survive_a_restart():
    settings.app_name = "From the container"
    await settings_store.load()
    await settings_store.apply({"app_name": "From the panel"})

    # Simulate the process coming back up with the same environment.
    settings.app_name = "From the container"
    settings_store.reset_state()
    await settings_store.load()

    assert settings.app_name == "From the panel"


async def test_resetting_an_override_returns_to_the_environment():
    settings.app_name = "From the container"
    await settings_store.load()
    await settings_store.apply({"app_name": "From the panel"})

    await settings_store.reset("app_name")

    assert settings.app_name == "From the container"
    assert settings_store.current()["app_name"]["overridden"] is False
    assert await db.get_settings() == {}


async def test_lists_and_numbers_survive_the_round_trip():
    await settings_store.load()

    await settings_store.apply({
        "ble_scanners": ["AA:BB:CC:DD:EE:FF"],
        "ble_min_rssi": -55,
        "presence_modes": ["local_network", "ha_ble"],
    })
    settings_store.reset_state()
    await settings_store.load()

    assert settings.ble_scanners == ["AA:BB:CC:DD:EE:FF"]
    assert settings.ble_min_rssi == -55
    assert settings.presence_modes == ["local_network", "ha_ble"]


async def test_bootstrap_settings_are_not_editable():
    """The app cannot read its own database to discover where its database is,
    and a bad admin password would lock the panel that fixes it."""
    for key in ("ha_base_url", "ha_token", "db_path", "admin_password", "admin_username"):
        assert key not in settings_store.EDITABLE
        with pytest.raises(ValueError):
            await settings_store.apply({key: "nope"})


# ---------------------------------------------------------------------------
# Seeding, so environment variables can be dropped safely
# ---------------------------------------------------------------------------

async def test_seeding_keeps_customised_values_so_the_variables_can_be_removed():
    settings.guest_url = "https://guests.example.com"
    settings.local_network_cidrs = ["192.168.0.0/16"]
    await settings_store.load()

    await settings_store.seed_from_environment()

    # The next boot has no environment variables at all — the values persist.
    settings.guest_url = ""
    settings.local_network_cidrs = []
    settings_store.reset_state()
    await settings_store.load()

    assert settings.guest_url == "https://guests.example.com"
    assert settings.local_network_cidrs == ["192.168.0.0/16"]


async def test_seeding_ignores_values_left_at_their_default():
    """Otherwise the panel opens showing a dozen "overridden" badges for
    settings nobody ever touched."""
    settings.app_name = "Home Access"  # the declared default
    settings.guest_url = "https://guests.example.com"
    await settings_store.load()

    await settings_store.seed_from_environment()

    stored = await db.get_settings()
    assert "guest_url" in stored
    assert "app_name" not in stored


async def test_seeding_never_overwrites_an_admin_edit():
    await settings_store.load()
    await settings_store.apply({"app_name": "Chosen in the panel"})

    settings.guest_url = "https://from-the-container.example.com"
    await settings_store.seed_from_environment()

    assert settings.app_name == "Chosen in the panel"
    assert "guest_url" not in await db.get_settings()


# ---------------------------------------------------------------------------
# Which changes need the Home Assistant listener restarted
# ---------------------------------------------------------------------------

async def test_presence_modes_reports_that_a_reconnect_is_needed():
    """Whether we subscribe to Bluetooth is decided when the socket connects."""
    await settings_store.load()

    assert await settings_store.apply({"presence_modes": ["ha_ble"]}) is True
    assert await settings_store.apply({"app_name": "Anything"}) is False
