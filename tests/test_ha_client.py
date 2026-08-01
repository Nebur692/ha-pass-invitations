import httpx
import pytest

from app import ha_client


@pytest.fixture
async def mock_http_client(monkeypatch):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(
        base_url="http://homeassistant.local:8123",
        transport=httpx.MockTransport(handler),
    )
    monkeypatch.setattr(ha_client, "_client", client)
    yield requests
    await client.aclose()


async def test_fire_event_posts_to_home_assistant_event_endpoint(mock_http_client):
    result = await ha_client.fire_event("ha_pass_activity", {"activity": "command"})

    assert result == {"ok": True}
    assert len(mock_http_client) == 1
    request = mock_http_client[0]
    assert request.method == "POST"
    assert request.url.path == "/api/events/ha_pass_activity"
    assert request.read() == b'{"activity":"command"}'


async def test_fire_event_does_not_retry_failed_posts(monkeypatch):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500, request=request)

    client = httpx.AsyncClient(
        base_url="http://homeassistant.local:8123",
        transport=httpx.MockTransport(handler),
    )
    monkeypatch.setattr(ha_client, "_client", client)

    with pytest.raises(httpx.HTTPStatusError):
        await ha_client.fire_event("ha_pass_activity", {"activity": "command"})

    assert len(requests) == 1
    await client.aclose()


async def test_logbook_log_posts_to_home_assistant_service_endpoint(mock_http_client):
    result = await ha_client.logbook_log({
        "name": "HAPass",
        "message": "Guest used light.turn_on",
    })

    assert result == {"ok": True}
    assert len(mock_http_client) == 1
    request = mock_http_client[0]
    assert request.method == "POST"
    assert request.url.path == "/api/services/logbook/log"
    assert request.read() == b'{"name":"HAPass","message":"Guest used light.turn_on"}'


# ---------------------------------------------------------------------------
# Bluetooth advertisements relayed by Home Assistant
# ---------------------------------------------------------------------------

async def test_ble_event_from_home_assistant_reaches_the_presence_store(sample_token):
    """Uses the real payload shape observed on a live HA 2026.7.2 socket:
    batches of {"add": [...]} where each entry carries address, rssi, source,
    service_uuids and service_data."""
    import time

    from app import database as db
    from app import presence

    secret = "device-secret"
    await db.claim_token_binding(sample_token["id"], secret, int(time.time()))
    uuid = presence.uuid_for(secret, presence.current_window())

    await ha_client._handle_ble_event({"add": [
        # A neighbour's sensor — real payload, must be ignored.
        {"address": "A4:C1:38:9B:6B:42", "rssi": -63, "source": "B8:D6:1A:8A:CE:96",
         "service_uuids": [], "service_data": {"0000fe95-0000-1000-8000-00805f9b34fb": "58585b05"}},
        {"address": "5E:11:22:33:44:55", "rssi": -52, "source": "B8:D6:1A:89:52:36",
         "service_uuids": [uuid], "service_data": {}},
    ]})

    seen = await presence.recent_observations(sample_token["id"])
    assert len(seen) == 1
    assert seen[0]["source"] == "B8:D6:1A:89:52:36"
    assert seen[0]["rssi"] == -52


async def test_ble_event_with_a_malformed_entry_does_not_break_the_batch(sample_token):
    from app import presence

    await ha_client._handle_ble_event({"add": [{"service_uuids": None}, {}]})
    await ha_client._handle_ble_event({})

    assert await presence.recent_observations(sample_token["id"]) == []
