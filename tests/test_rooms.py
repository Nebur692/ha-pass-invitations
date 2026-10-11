"""The guest page groups its devices by Home Assistant area."""
import time
from unittest.mock import AsyncMock

import pytest

from app import database as db
from app import ha_client

AREAS = [
    {"area_id": "entrada", "name": "Entrada"},
    {"area_id": "salon", "name": "Salón"},
    {"area_id": "garaje", "name": "Garaje"},
]
# Shaped like the author's home: nearly every entity takes its device's area.
DEVICES = [
    {"id": "dev-nuki", "area_id": "entrada"},
    {"id": "dev-lamp", "area_id": "salon"},
    {"id": "dev-loose", "area_id": None},
    {"id": "dev-ghost", "area_id": "trastero-borrado"},
]
ENTITIES = [
    {"entity_id": "lock.front_door", "device_id": "dev-nuki", "area_id": None},
    {"entity_id": "light.sofa", "device_id": "dev-lamp", "area_id": None},
    # Its own area wins over its device's.
    {"entity_id": "light.porch", "device_id": "dev-lamp", "area_id": "entrada"},
    {"entity_id": "button.gate", "device_id": None, "area_id": "garaje"},
    {"entity_id": "switch.loose", "device_id": "dev-loose", "area_id": None},
    {"entity_id": "switch.ghost", "device_id": "dev-ghost", "area_id": None},
]


@pytest.fixture
def registries(monkeypatch):
    fetch = AsyncMock(return_value=(AREAS, ENTITIES, DEVICES))
    monkeypatch.setattr(ha_client, "_fetch_registries", fetch)
    monkeypatch.setattr(ha_client, "_areas_at", 0.0)
    return fetch


async def test_an_entity_takes_its_devices_area(registries):
    areas, entity_areas = await ha_client.get_entity_areas()

    assert areas == [("entrada", "Entrada"), ("salon", "Salón"), ("garaje", "Garaje")]
    assert entity_areas == {
        "lock.front_door": "entrada",   # from its device
        "light.sofa": "salon",          # from its device
        "light.porch": "entrada",       # its own, over the device's
        "button.gate": "garaje",        # its own, no device
    }
    # No area anywhere, or an area that no longer exists: not in the map.
    assert "switch.loose" not in entity_areas
    assert "switch.ghost" not in entity_areas


async def test_the_registries_are_read_once_per_ten_minutes(registries):
    await ha_client.get_entity_areas()
    await ha_client.get_entity_areas()
    assert registries.await_count == 1

    await ha_client.get_entity_areas(force=True)
    assert registries.await_count == 2


async def test_a_failure_is_raised_and_not_cached(registries):
    registries.side_effect = RuntimeError("HA down")
    with pytest.raises(RuntimeError):
        await ha_client.get_entity_areas()

    registries.side_effect = None
    areas, _ = await ha_client.get_entity_areas()
    assert areas


# ---------------------------------------------------------------------------
# What the page receives
# ---------------------------------------------------------------------------

async def _token(entity_ids):
    return await db.create_token(
        label="Guest",
        slug="guest-rooms",
        entity_ids=entity_ids,
        expires_at=int(time.time()) + 3600,
        ip_allowlist=None,
    )


async def test_state_groups_by_room_in_home_assistants_order(client, mock_ha_client):
    mock_ha_client["get_entity_areas"].return_value = (
        [("entrada", "Entrada"), ("salon", "Salón"), ("garaje", "Garaje"), ("cocina", "Cocina")],
        {"lock.front_door": "entrada", "light.sofa": "salon",
         "light.porch": "entrada", "light.kitchen": "cocina"},
    )
    token = await _token(["light.sofa", "switch.loose", "lock.front_door", "light.porch"])

    resp = await client.get(f"/g/{token['slug']}/state")

    assert resp.status_code == 200
    data = resp.json()
    # Inside a room, the order the token itself gives (the page sorts by kind).
    entrada = [e for e in data["entities"] if e in ("lock.front_door", "light.porch")]
    assert data["rooms"] == [
        {"name": "Entrada", "entities": entrada},
        {"name": "Salón", "entities": ["light.sofa"]},
        {"name": None, "entities": ["switch.loose"]},
    ]
    # Rooms the guest has nothing in are not named to them.
    assert "Cocina" not in resp.text and "Garaje" not in resp.text


async def test_without_areas_the_page_gets_none_and_keeps_the_flat_list(
    client, mock_ha_client
):
    mock_ha_client["get_entity_areas"].side_effect = RuntimeError("HA down")
    token = await _token(["light.sofa", "lock.front_door"])

    resp = await client.get(f"/g/{token['slug']}/state")

    assert resp.status_code == 200
    assert resp.json()["rooms"] is None
    assert resp.json()["entities"] == ["light.sofa", "lock.front_door"]
