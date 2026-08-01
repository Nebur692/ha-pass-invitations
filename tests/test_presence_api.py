"""Presence enforcement and native-app enrollment over HTTP."""
import time

import pytest

from app import database as db
from app import presence
from app.config import settings
from app.models import NEVER_EXPIRES_SECONDS
from app.routers.guest import BINDING_HEADER

DOOR = "AA:BB:CC:DD:EE:FF"


@pytest.fixture
async def lock_token(test_db):
    """A token for a lock — one of the LOCAL_ONLY_DOMAINS that presence gates."""
    return await db.create_token(
        label="Front door",
        slug="front-door",
        entity_ids=["lock.front_door", "light.hall"],
        expires_at=int(time.time()) + 3600,
        ip_allowlist=None,
    )


async def _bind_and_see(token, rssi=-55, source=DOOR):
    secret = "device-secret"
    await db.claim_token_binding(token["id"], secret, int(time.time()))
    uuid = presence.uuid_for(secret, presence.current_window())
    await presence.record_advertisement([uuid], source, rssi)
    return secret


# ---------------------------------------------------------------------------
# Enforcement on the command endpoint
# ---------------------------------------------------------------------------

async def test_lock_is_refused_off_the_network_and_away_from_the_door(
    client, lock_token, mock_ha_client
):
    settings.presence_modes = ["local_network", "ha_ble"]
    settings.local_network_cidrs = ["192.168.0.0/16"]
    settings.ble_scanners = [DOOR]

    resp = await client.post(
        f"/g/{lock_token['slug']}/command",
        json={"entity_id": "lock.front_door", "service": "unlock"},
        headers={"X-Forwarded-For": "203.0.113.7"},
    )

    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


async def test_bluetooth_alone_opens_the_lock_with_no_wifi(
    client, lock_token, mock_ha_client
):
    """The feature the Android app exists for: the guest never joins the WiFi."""
    settings.presence_modes = ["local_network", "ha_ble"]
    settings.presence_policy = "any"
    settings.local_network_cidrs = ["192.168.0.0/16"]
    settings.ble_scanners = [DOOR]
    secret = await _bind_and_see(lock_token)

    resp = await client.post(
        f"/g/{lock_token['slug']}/command",
        json={"entity_id": "lock.front_door", "service": "unlock"},
        headers={"X-Forwarded-For": "203.0.113.7", BINDING_HEADER: secret},
    )

    assert resp.status_code == 200
    mock_ha_client["call_service"].assert_called_once()


async def test_lights_are_never_gated_by_presence(client, lock_token, mock_ha_client):
    """Only things that open physically are restricted — a guest can turn the
    hall light off from the sofa."""
    settings.presence_modes = ["local_network", "ha_ble"]
    settings.local_network_cidrs = ["192.168.0.0/16"]
    settings.ble_scanners = [DOOR]

    resp = await client.post(
        f"/g/{lock_token['slug']}/command",
        json={"entity_id": "light.hall", "service": "turn_on"},
        headers={"X-Forwarded-For": "203.0.113.7"},
    )

    assert resp.status_code == 200


async def test_default_configuration_is_unchanged(client, lock_token, mock_ha_client):
    """Existing installations upgrade without their locks suddenly refusing."""
    assert settings.presence_modes == ["local_network"]
    settings.local_network_cidrs = []

    resp = await client.post(
        f"/g/{lock_token['slug']}/command",
        json={"entity_id": "lock.front_door", "service": "unlock"},
        headers={"X-Forwarded-For": "203.0.113.7"},
    )

    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Enrollment
# ---------------------------------------------------------------------------

async def test_enroll_hands_the_secret_over_once(client, lock_token):
    settings.presence_modes = ["ha_ble"]

    first = await client.post(f"/g/{lock_token['slug']}/enroll")
    assert first.status_code == 200
    body = first.json()
    secret = body["binding_secret"]
    assert body["presence"]["bluetooth"] is True
    assert body["presence"]["uuid_prefix"] == presence.UUID_PREFIX
    assert body["presence"]["window_seconds"] == presence.CODE_WINDOW_SECONDS

    # Same device coming back: still authorised, but the secret is not repeated
    # — re-sending it every time would put it back within reach of a leaked link.
    again = await client.post(
        f"/g/{lock_token['slug']}/enroll", headers={BINDING_HEADER: secret}
    )
    assert again.status_code == 200
    assert "binding_secret" not in again.json()


async def test_enroll_refuses_a_second_device(client, lock_token):
    await client.post(f"/g/{lock_token['slug']}/enroll")

    resp = await client.post(
        f"/g/{lock_token['slug']}/enroll", headers={BINDING_HEADER: "not-the-secret"}
    )

    assert resp.status_code == 403


async def test_enroll_reports_bluetooth_off_when_not_configured(client, lock_token):
    settings.presence_modes = ["local_network"]

    body = (await client.post(f"/g/{lock_token['slug']}/enroll")).json()

    assert body["presence"]["bluetooth"] is False
    assert body["presence"]["uuid_prefix"] is None


async def test_the_app_can_authenticate_with_the_header_instead_of_a_cookie(
    client, lock_token
):
    secret = (await client.post(f"/g/{lock_token['slug']}/enroll")).json()["binding_secret"]

    ok = await client.get(
        f"/g/{lock_token['slug']}/state", headers={BINDING_HEADER: secret}
    )
    assert ok.status_code == 200

    wrong = await client.get(
        f"/g/{lock_token['slug']}/state", headers={BINDING_HEADER: "wrong"}
    )
    assert wrong.status_code == 403


# ---------------------------------------------------------------------------
# Android app association
# ---------------------------------------------------------------------------

async def test_assetlinks_404s_until_an_app_is_published(client):
    settings.android_cert_fingerprints = []
    assert (await client.get("/.well-known/assetlinks.json")).status_code == 404


async def test_assetlinks_describes_the_published_app(client):
    settings.android_cert_fingerprints = ["AA:BB"]
    try:
        resp = await client.get("/.well-known/assetlinks.json")
        assert resp.status_code == 200
        target = resp.json()[0]["target"]
        assert target["namespace"] == "android_app"
        assert target["package_name"] == settings.android_package
        assert target["sha256_cert_fingerprints"] == ["AA:BB"]
    finally:
        settings.android_cert_fingerprints = []


# ---------------------------------------------------------------------------
# Admin: status and door calibration
# ---------------------------------------------------------------------------

async def test_presence_status_reports_the_live_configuration(client, admin_session):
    settings.presence_modes = ["local_network", "ha_ble"]
    settings.ble_scanners = [DOOR]
    settings.ble_min_rssi = -65

    body = (await client.get("/admin/presence", cookies=admin_session)).json()

    assert body["modes"] == ["local_network", "ha_ble"]
    assert body["bluetooth"]["enabled"] is True
    assert body["bluetooth"]["scanners"] == [
        {"source": DOOR, "name": None, "approximate": False}
    ]
    assert body["bluetooth"]["min_rssi"] == -65


async def test_scanners_are_shown_by_name_when_home_assistant_knows_them(
    client, admin_session, mock_ha_client
):
    """A scanner advertises from its WiFi MAC plus two on ESP32 hardware, so
    the panel can say "Persiana recibidor" instead of a bare address."""
    settings.presence_modes = ["ha_ble"]
    settings.ble_scanners = ["44:17:93:AD:0C:7E"]
    mock_ha_client["get_device_mac_names"].return_value = {
        "44:17:93:AD:0C:7C": "Persiana recibidor"
    }

    body = (await client.get("/admin/presence", cookies=admin_session)).json()

    assert body["bluetooth"]["scanners"] == [
        {"source": "44:17:93:AD:0C:7E", "name": "Persiana recibidor", "approximate": True}
    ]


async def test_a_broken_device_registry_does_not_break_the_panel(
    client, admin_session, mock_ha_client
):
    """A nameless scanner is a cosmetic loss, not a reason to fail the page."""
    settings.presence_modes = ["ha_ble"]
    settings.ble_scanners = [DOOR]
    mock_ha_client["get_device_mac_names"].side_effect = RuntimeError("HA unreachable")

    resp = await client.get("/admin/presence", cookies=admin_session)

    assert resp.status_code == 200
    assert resp.json()["bluetooth"]["scanners"][0]["name"] is None


async def test_presence_status_requires_admin(client):
    assert (await client.get("/admin/presence")).status_code == 401


async def test_calibration_needs_bluetooth_enabled(client, admin_session):
    settings.presence_modes = ["local_network"]

    resp = await client.post("/admin/presence/calibration", cookies=admin_session)

    assert resp.status_code == 409


async def test_calibration_shows_which_scanner_hears_a_device_best(client, admin_session):
    """The admin carries any Bluetooth gadget to the door and reads off the
    winner — scanner MACs cannot be mapped to Home Assistant device names."""
    settings.presence_modes = ["ha_ble"]
    started = await client.post("/admin/presence/calibration", cookies=admin_session)
    assert started.status_code == 200
    assert started.json()["active"] is True

    # Same gadget heard by two scanners; the hallway one is much closer.
    await presence.record_advertisement(
        [], "B8:D6:1A:89:52:36", -45, address="BL:UB:UT:00:00:01", local_name="BLU Button1"
    )
    await presence.record_advertisement(
        [], "44:17:93:CE:E7:2E", -88, address="BL:UB:UT:00:00:01", local_name=None
    )

    body = (await client.get("/admin/presence/calibration", cookies=admin_session)).json()

    device = next(d for d in body["devices"] if d["address"] == "BL:UB:UT:00:00:01")
    assert device["name"] == "BLU Button1"
    assert all("name" in s and "approximate" in s for s in device["scanners"])
    assert [s["source"] for s in device["scanners"]] == [
        "B8:D6:1A:89:52:36",  # strongest first — this is the door
        "44:17:93:CE:E7:2E",
    ]
    assert device["scanners"][0]["rssi"] == -45


async def test_nothing_is_recorded_while_calibration_is_off(client, admin_session):
    """A busy house pushes hundreds of advertisements a minute; holding them
    forever would be pointless memory."""
    await presence.record_advertisement(
        [], "B8:D6:1A:89:52:36", -45, address="BL:UB:UT:00:00:01"
    )

    body = (await client.get("/admin/presence/calibration", cookies=admin_session)).json()

    assert body["active"] is False
    assert body["devices"] == []


async def test_calibration_can_be_stopped(client, admin_session):
    settings.presence_modes = ["ha_ble"]
    await client.post("/admin/presence/calibration", cookies=admin_session)
    await presence.record_advertisement([], "AA:AA", -45, address="BL:UB:UT:00:00:01")

    stopped = await client.delete("/admin/presence/calibration", cookies=admin_session)

    assert stopped.json()["active"] is False
    assert stopped.json()["devices"] == []
