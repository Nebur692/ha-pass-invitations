"""Editing runtime settings from the admin panel."""
import pytest

from app import settings_store
from app.config import settings


@pytest.fixture(autouse=True)
async def _clean_store(test_db):
    settings_store.reset_state()
    original = {name: getattr(settings, name) for name in settings_store.EDITABLE}
    await settings_store.load()
    yield
    for name, value in original.items():
        setattr(settings, name, value)
    settings_store.reset_state()


async def test_settings_are_listed_with_their_origin(client, admin_session):
    body = (await client.get("/admin/settings", cookies=admin_session)).json()

    assert set(body["settings"]) == set(settings_store.EDITABLE)
    assert body["settings"]["app_name"]["overridden"] is False
    assert "presence_modes" in body["needs_reconnect"]


async def test_settings_require_admin(client):
    assert (await client.get("/admin/settings")).status_code == 401
    assert (await client.patch("/admin/settings", json={"app_name": "x"})).status_code == 401


async def test_saving_a_setting_takes_effect_immediately(client, admin_session):
    resp = await client.patch(
        "/admin/settings", json={"app_name": "Casa"}, cookies=admin_session
    )

    assert resp.status_code == 200
    assert settings.app_name == "Casa"
    assert resp.json()["settings"]["app_name"]["overridden"] is True


async def test_only_the_fields_sent_are_changed(client, admin_session):
    await client.patch("/admin/settings", json={"app_name": "Casa"}, cookies=admin_session)

    await client.patch("/admin/settings", json={"ble_min_rssi": -50}, cookies=admin_session)

    assert settings.app_name == "Casa"
    assert settings.ble_min_rssi == -50


async def test_turning_bluetooth_on_reconnects_home_assistant(
    client, admin_session, mock_ha_client
):
    """Whether we subscribe to advertisements is decided when the socket
    connects, so this would otherwise silently wait for a container restart —
    the exact friction this whole feature removes."""
    resp = await client.patch(
        "/admin/settings",
        json={"presence_modes": ["local_network", "ha_ble"]},
        cookies=admin_session,
    )

    assert resp.status_code == 200
    mock_ha_client["restart_ws_listener"].assert_awaited_once()


async def test_an_ordinary_change_does_not_disturb_home_assistant(
    client, admin_session, mock_ha_client
):
    await client.patch("/admin/settings", json={"app_name": "Casa"}, cookies=admin_session)

    mock_ha_client["restart_ws_listener"].assert_not_awaited()


async def test_resetting_returns_to_the_environment_value(client, admin_session):
    environment_value = settings.app_name
    await client.patch("/admin/settings", json={"app_name": "Casa"}, cookies=admin_session)

    resp = await client.delete("/admin/settings/app_name", cookies=admin_session)

    assert resp.status_code == 200
    assert settings.app_name == environment_value


async def test_resetting_something_that_is_not_a_setting_is_a_404(client, admin_session):
    resp = await client.delete("/admin/settings/ha_token", cookies=admin_session)

    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Validation — a typo here could lock the admin out of their own front door
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    {"timezone": "Mars/Olympus"},
    {"local_network_cidrs": ["192.168.0.0/99"]},
    {"presence_modes": ["telepathy"]},
    {"presence_policy": "maybe"},
    {"ble_scanners": ["not-a-mac"]},
    {"ble_min_rssi": 40},
    {"brand_primary": "red"},
    {"app_name": ""},
    {"guest_url": "ftp://example.com"},
    {"access_log_retention_days": 0},
    {"ha_token": "stolen"},
])
async def test_invalid_values_are_refused(client, admin_session, payload):
    resp = await client.patch("/admin/settings", json=payload, cookies=admin_session)

    assert resp.status_code == 422


async def test_an_empty_request_is_refused(client, admin_session):
    assert (await client.patch("/admin/settings", json={}, cookies=admin_session)).status_code == 400


async def test_a_rejected_value_changes_nothing(client, admin_session):
    before = settings.timezone

    await client.patch(
        "/admin/settings",
        json={"app_name": "Casa", "timezone": "Mars/Olympus"},
        cookies=admin_session,
    )

    assert settings.timezone == before
    assert settings.app_name != "Casa"  # the whole request was refused
