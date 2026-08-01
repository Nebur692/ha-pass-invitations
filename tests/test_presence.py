"""Server-verified proofs that the guest is physically present.

The point of every test here is the threat model in app/presence.py: the guest
is the adversary, so a proof is only worth anything if the server derives it
from something the guest cannot assert.
"""
import time

import pytest

from app import database as db
from app import presence
from app.config import settings


# ---------------------------------------------------------------------------
# The rotating code
# ---------------------------------------------------------------------------

def test_uuid_round_trips_through_extract_code():
    window = presence.current_window()
    uuid = presence.uuid_for("a-secret", window)
    assert uuid.startswith(presence.UUID_PREFIX)
    assert len(uuid) == 36
    assert presence.extract_code(uuid) == presence.code_for("a-secret", window)


def test_foreign_advertisements_are_ignored():
    # Real payload seen on the wire from a Xiaomi sensor — must not be mistaken
    # for ours just because something else is advertising nearby.
    assert presence.extract_code("0000fe95-0000-1000-8000-00805f9b34fb") is None
    assert presence.extract_code("nonsense") is None


def test_code_changes_every_window():
    window = presence.current_window()
    assert presence.code_for("s", window) != presence.code_for("s", window + 1)


def test_different_secrets_give_different_codes():
    window = presence.current_window()
    assert presence.code_for("secret-a", window) != presence.code_for("secret-b", window)


# ---------------------------------------------------------------------------
# Recording advertisements relayed by Home Assistant
# ---------------------------------------------------------------------------

async def _bind(token, secret="device-secret"):
    await db.claim_token_binding(token["id"], secret, int(time.time()))
    return secret


async def test_advertisement_from_a_bound_token_is_recorded(sample_token):
    secret = await _bind(sample_token)
    uuid = presence.uuid_for(secret, presence.current_window())

    matched = await presence.record_advertisement([uuid], "AA:BB:CC:DD:EE:FF", -55)

    assert matched == sample_token["id"]
    seen = await presence.recent_observations(sample_token["id"])
    assert len(seen) == 1
    assert seen[0]["source"] == "AA:BB:CC:DD:EE:FF"
    assert seen[0]["rssi"] == -55


async def test_advertisement_with_an_unknown_code_is_ignored(sample_token):
    await _bind(sample_token)
    stranger = presence.uuid_for("some-other-device", presence.current_window())

    assert await presence.record_advertisement([stranger], "AA:BB:CC:DD:EE:FF", -55) is None
    assert await presence.recent_observations(sample_token["id"]) == []


async def test_neighbouring_windows_are_accepted_for_clock_skew(sample_token):
    secret = await _bind(sample_token)
    previous = presence.uuid_for(secret, presence.current_window() - 1)

    assert await presence.record_advertisement([previous], "AA:BB:CC:DD:EE:FF", -55) \
        == sample_token["id"]


async def test_a_stale_code_no_longer_opens_anything(sample_token):
    """The whole reason the code rotates: a value captured at the door and
    replayed later — say by a board someone hid there — must stop working."""
    secret = await _bind(sample_token)
    captured = presence.uuid_for(secret, presence.current_window() - 10)

    assert await presence.record_advertisement([captured], "AA:BB:CC:DD:EE:FF", -55) is None


async def test_revoked_tokens_drop_out_of_the_code_table(sample_token):
    secret = await _bind(sample_token)
    await db.revoke_token(sample_token["id"])
    await presence.reset_state()
    uuid = presence.uuid_for(secret, presence.current_window())

    assert await presence.record_advertisement([uuid], "AA:BB:CC:DD:EE:FF", -55) is None


# ---------------------------------------------------------------------------
# The local_network provider — unchanged behaviour
# ---------------------------------------------------------------------------

async def test_local_network_unconfigured_allows_everything(sample_token):
    settings.presence_modes = ["local_network"]
    settings.local_network_cidrs = []

    await presence.check(sample_token["id"], "203.0.113.7")  # must not raise


async def test_local_network_rejects_an_outside_address(sample_token):
    settings.presence_modes = ["local_network"]
    settings.local_network_cidrs = ["192.168.0.0/16"]

    with pytest.raises(presence.PresenceDenied) as exc:
        await presence.check(sample_token["id"], "203.0.113.7")
    assert exc.value.reason == "not_on_local_network"


async def test_local_network_accepts_an_inside_address(sample_token):
    settings.presence_modes = ["local_network"]
    settings.local_network_cidrs = ["192.168.0.0/16"]

    await presence.check(sample_token["id"], "192.168.1.50")


# ---------------------------------------------------------------------------
# The ha_ble provider
# ---------------------------------------------------------------------------

async def _see(token_id, secret, source="AA:BB:CC:DD:EE:FF", rssi=-55):
    uuid = presence.uuid_for(secret, presence.current_window())
    return await presence.record_advertisement([uuid], source, rssi)


async def test_ble_fails_closed_when_no_door_scanner_is_selected(sample_token):
    """"Heard by any scanner in the house" is not "at the door". Accepting it
    silently would be a proof in name only, so the mode stays inactive."""
    secret = await _bind(sample_token)
    settings.presence_modes = ["ha_ble"]
    settings.ble_scanners = []
    await _see(sample_token["id"], secret)

    with pytest.raises(presence.PresenceDenied) as exc:
        await presence.check(sample_token["id"], "203.0.113.7")
    assert exc.value.reason == "ble_not_configured"


async def test_ble_accepts_a_close_sighting_at_the_door(sample_token):
    secret = await _bind(sample_token)
    settings.presence_modes = ["ha_ble"]
    settings.ble_scanners = ["AA:BB:CC:DD:EE:FF"]
    settings.ble_min_rssi = -70
    await _see(sample_token["id"], secret, rssi=-55)

    await presence.check(sample_token["id"], "203.0.113.7")  # not on the WiFi at all


async def test_ble_rejects_when_never_seen(sample_token):
    await _bind(sample_token)
    settings.presence_modes = ["ha_ble"]
    settings.ble_scanners = ["AA:BB:CC:DD:EE:FF"]

    with pytest.raises(presence.PresenceDenied) as exc:
        await presence.check(sample_token["id"], "192.168.1.50")
    assert exc.value.reason == "ble_not_seen"


async def test_ble_rejects_a_sighting_from_another_room(sample_token):
    secret = await _bind(sample_token)
    settings.presence_modes = ["ha_ble"]
    settings.ble_scanners = ["AA:BB:CC:DD:EE:FF"]
    await _see(sample_token["id"], secret, source="11:22:33:44:55:66", rssi=-40)

    with pytest.raises(presence.PresenceDenied) as exc:
        await presence.check(sample_token["id"], "192.168.1.50")
    assert exc.value.reason == "ble_wrong_scanner"


async def test_ble_rejects_a_weak_sighting(sample_token):
    secret = await _bind(sample_token)
    settings.presence_modes = ["ha_ble"]
    settings.ble_scanners = ["AA:BB:CC:DD:EE:FF"]
    settings.ble_min_rssi = -60
    await _see(sample_token["id"], secret, rssi=-88)

    with pytest.raises(presence.PresenceDenied) as exc:
        await presence.check(sample_token["id"], "192.168.1.50")
    assert exc.value.reason == "ble_too_far"


async def test_ble_scanner_match_is_case_insensitive(sample_token):
    secret = await _bind(sample_token)
    settings.presence_modes = ["ha_ble"]
    settings.ble_scanners = ["aa:bb:cc:dd:ee:ff"]
    await _see(sample_token["id"], secret, source="AA:BB:CC:DD:EE:FF")

    await presence.check(sample_token["id"], "203.0.113.7")


async def test_ble_sightings_expire(sample_token, monkeypatch):
    secret = await _bind(sample_token)
    settings.presence_modes = ["ha_ble"]
    settings.ble_scanners = ["AA:BB:CC:DD:EE:FF"]
    await _see(sample_token["id"], secret)

    # Walk away: the sighting is now older than the freshness window. Resolve
    # the target instant first — the lambda replaces time.time() itself, so
    # calling it inside would recurse.
    later = time.time() + settings.ble_max_age_seconds + 5
    monkeypatch.setattr(presence.time, "time", lambda: later)
    with pytest.raises(presence.PresenceDenied) as exc:
        await presence.check(sample_token["id"], "192.168.1.50")
    assert exc.value.reason == "ble_not_seen"


# ---------------------------------------------------------------------------
# Combining providers
# ---------------------------------------------------------------------------

async def test_any_policy_lets_bluetooth_stand_in_for_the_wifi(sample_token):
    """The whole point of the app: off the home network, but at the door."""
    secret = await _bind(sample_token)
    settings.presence_modes = ["local_network", "ha_ble"]
    settings.presence_policy = "any"
    settings.local_network_cidrs = ["192.168.0.0/16"]
    settings.ble_scanners = ["AA:BB:CC:DD:EE:FF"]
    await _see(sample_token["id"], secret)

    await presence.check(sample_token["id"], "203.0.113.7")


async def test_any_policy_still_rejects_when_nothing_is_satisfied(sample_token):
    await _bind(sample_token)
    settings.presence_modes = ["local_network", "ha_ble"]
    settings.presence_policy = "any"
    settings.local_network_cidrs = ["192.168.0.0/16"]
    settings.ble_scanners = ["AA:BB:CC:DD:EE:FF"]

    with pytest.raises(presence.PresenceDenied):
        await presence.check(sample_token["id"], "203.0.113.7")


async def test_all_policy_requires_every_mode(sample_token):
    secret = await _bind(sample_token)
    settings.presence_modes = ["local_network", "ha_ble"]
    settings.presence_policy = "all"
    settings.local_network_cidrs = ["192.168.0.0/16"]
    settings.ble_scanners = ["AA:BB:CC:DD:EE:FF"]
    await _see(sample_token["id"], secret)

    # Bluetooth alone is no longer enough.
    with pytest.raises(presence.PresenceDenied):
        await presence.check(sample_token["id"], "203.0.113.7")
    # On the WiFi and at the door: both satisfied.
    await presence.check(sample_token["id"], "192.168.1.50")


async def test_no_modes_configured_allows_everything(sample_token):
    settings.presence_modes = []
    await presence.check(sample_token["id"], "203.0.113.7")


async def test_calibration_evicts_the_stalest_device_when_full():
    """A real house pushed 152 distinct devices in 45 seconds, nearly all of
    them one-off random MACs from passers-by. The buffer therefore fills long
    before the admin reaches the door, and refusing new entries would drop the
    one device that matters."""
    await presence.start_calibration()
    for i in range(presence.MAX_CALIBRATION_DEVICES):
        await presence.record_advertisement([], "SCANNER", -90, address=f"PASSERBY:{i}")

    await presence.record_advertisement(
        [], "DOOR", -45, address="MY:GADGET", local_name="BLU Button1"
    )

    snapshot = await presence.calibration_snapshot()
    addresses = {d["address"] for d in snapshot["devices"]}
    assert "MY:GADGET" in addresses
    assert len(snapshot["devices"]) <= presence.MAX_CALIBRATION_DEVICES
    assert "PASSERBY:0" not in addresses  # the stalest one made way


async def test_calibration_follows_a_device_across_scanners():
    """Home Assistant only ever names the nearest scanner, so walking to the
    door is what makes the door scanner show up — and win on signal."""
    await presence.start_calibration()
    await presence.record_advertisement([], "LIVING:ROOM", -80, address="MY:GADGET")
    await presence.record_advertisement([], "HALLWAY", -48, address="MY:GADGET")

    device = (await presence.calibration_snapshot())["devices"][0]

    assert [s["source"] for s in device["scanners"]] == ["HALLWAY", "LIVING:ROOM"]
    assert device["scanners"][0]["rssi"] == -48
