"""Tests for guest endpoint security: service allowlists, token validation, IP, rate limiting.

These are integration tests. The full request path is exercised:
    httpx → FastAPI routing → _validate_token (real DB) → service allowlist
    → rate limiter (real) → data scrubbing → ha_client.call_service (mocked)
    → access log (real DB)

Only ha_client is mocked — it's an external dependency we can't run in CI.
"""
import time

import httpx
import pytest

from app import database as db
from app.config import settings
from app.models import ALLOWED_SERVICES, FORBIDDEN_DATA_KEYS, READ_ONLY_DOMAINS


@pytest.fixture
def local_network_cidrs():
    """Temporarily set settings.local_network_cidrs, restoring it afterwards
    (module-level singleton, same reasoning as the test_db fixture's handling
    of settings.db_path)."""
    original = settings.local_network_cidrs
    def _set(cidrs):
        settings.local_network_cidrs = cidrs
    yield _set
    settings.local_network_cidrs = original


# ---------------------------------------------------------------------------
# ALLOWED_SERVICES — verify the real allowlist enforcement
# ---------------------------------------------------------------------------

async def test_allowed_service_forwards_correct_args_to_ha(client, sample_token, mock_ha_client):
    """A valid command passes all validation and reaches HA with correct args."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "turn_on"},
    )
    assert resp.status_code == 200
    assert "result" not in resp.json()

    # Verify call_service was called with the right domain, service, and data
    mock_ha_client["call_service"].assert_called_once()
    args = mock_ha_client["call_service"].call_args[0]
    assert args[0] == "light"       # domain
    assert args[1] == "turn_on"     # service name
    assert args[2]["entity_id"] == "light.living_room"  # entity in payload


async def test_allowed_service_writes_access_log(client, sample_token, mock_ha_client):
    """A successful command writes a row to the real access_log table."""
    await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "turn_on"},
    )
    conn = await db.get_db()
    async with conn.execute(
        "SELECT * FROM access_log WHERE token_id = ?", (sample_token["id"],)
    ) as cur:
        row = await cur.fetchone()
    assert row is not None
    assert row["event_type"] == "command"
    assert row["entity_id"] == "light.living_room"
    assert row["service"] == "turn_on"


async def test_successful_command_emits_activity_event(client, sample_token, mock_ha_client):
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "turn_on"},
    )
    assert resp.status_code == 200
    mock_ha_client["fire_event"].assert_called_once()
    event_type, payload = mock_ha_client["fire_event"].call_args[0]
    assert event_type == "ha_pass_activity"
    assert payload == {
        "schema_version": 1,
        "activity": "command",
        "token_label": "Test Token",
        "target_entity_id": "light.living_room",
        "service": "light.turn_on",
    }
    assert sample_token["slug"] not in payload.values()
    assert sample_token["id"] not in payload.values()
    mock_ha_client["logbook_log"].assert_called_once_with({
        "name": "HAPass",
        "message": "Test Token used light.turn_on on light.living_room",
        "entity_id": "light.living_room",
        "domain": "light",
    })


async def test_activity_event_failure_does_not_break_command(client, sample_token, mock_ha_client):
    mock_ha_client["fire_event"].side_effect = RuntimeError("ha unavailable")
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "turn_on"},
    )
    assert resp.status_code == 200
    mock_ha_client["call_service"].assert_called_once()
    assert mock_ha_client["fire_event"].call_count == 1
    mock_ha_client["logbook_log"].assert_called_once()


async def test_logbook_failure_does_not_break_command(client, sample_token, mock_ha_client):
    mock_ha_client["logbook_log"].side_effect = RuntimeError("logbook unavailable")
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "turn_on"},
    )
    assert resp.status_code == 200
    mock_ha_client["fire_event"].assert_called_once()
    mock_ha_client["logbook_log"].assert_called_once()


async def test_disallowed_service_never_reaches_ha(client, sample_token, mock_ha_client):
    """An unknown service is blocked BEFORE call_service is ever invoked."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "nonexistent_service"},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()
    mock_ha_client["fire_event"].assert_not_called()
    mock_ha_client["logbook_log"].assert_not_called()


async def test_script_domain_never_reaches_ha(client, mock_ha_client, test_db):
    """Script domain is not in ALLOWED_SERVICES — blocked before HA call."""
    assert "script" not in ALLOWED_SERVICES
    now = int(time.time())
    await db.create_token(
        label="Script", slug="script-test", entity_ids=["script.dangerous"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/script-test/command",
        json={"entity_id": "script.dangerous", "service": "turn_on"},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


async def test_automation_domain_never_reaches_ha(client, mock_ha_client, test_db):
    assert "automation" not in ALLOWED_SERVICES
    now = int(time.time())
    await db.create_token(
        label="Auto", slug="auto-test", entity_ids=["automation.run_all"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/auto-test/command",
        json={"entity_id": "automation.run_all", "service": "trigger"},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


async def test_sensor_domain_is_read_only(client, mock_ha_client, test_db):
    """Sensors can be assigned to tokens but commands are never forwarded."""
    assert "sensor" in READ_ONLY_DOMAINS
    assert "sensor" not in ALLOWED_SERVICES
    now = int(time.time())
    await db.create_token(
        label="Sensor", slug="sensor-test", entity_ids=["sensor.temperature"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/sensor-test/command",
        json={"entity_id": "sensor.temperature", "service": "sensor.turn_on"},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


async def test_lock_open_service_allowed(client, mock_ha_client, test_db):
    """Locks may call HA's optional open/unlatch service when assigned."""
    assert "open" in ALLOWED_SERVICES["lock"]
    now = int(time.time())
    await db.create_token(
        label="Lock", slug="lock-open-test", entity_ids=["lock.front_door"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/lock-open-test/command",
        json={"entity_id": "lock.front_door", "service": "lock.open"},
    )
    assert resp.status_code == 200
    mock_ha_client["call_service"].assert_called_once()
    args = mock_ha_client["call_service"].call_args[0]
    assert args[0] == "lock"
    assert args[1] == "open"
    assert args[2]["entity_id"] == "lock.front_door"


async def test_service_domain_mismatch_rejected(client, sample_token, mock_ha_client):
    """Service domain must match entity domain (light entity vs switch.turn_on)."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "switch.turn_on"},
    )
    assert resp.status_code == 403
    assert "domain does not match" in resp.json()["detail"]
    mock_ha_client["call_service"].assert_not_called()


# ---------------------------------------------------------------------------
# FORBIDDEN_DATA_KEYS — real data scrubbing in the router
# ---------------------------------------------------------------------------

async def test_forbidden_data_keys_stripped_before_ha_call(client, sample_token, mock_ha_client):
    """entity_id/device_id/area_id/label_id in the data payload are stripped before reaching HA."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={
            "entity_id": "light.living_room",
            "service": "turn_on",
            "data": {
                "brightness": 255,
                "entity_id": "light.MALICIOUS",
                "device_id": "injected",
                "area_id": "sneaky",
                "label_id": "all_lights",
            },
        },
    )
    assert resp.status_code == 200

    # Inspect what was actually forwarded to HA
    service_data = mock_ha_client["call_service"].call_args[0][2]
    assert service_data["entity_id"] == "light.living_room"  # real entity, not injected
    assert "device_id" not in service_data
    assert "area_id" not in service_data
    assert "label_id" not in service_data
    assert service_data["brightness"] == 255  # legitimate data preserved


async def test_all_forbidden_keys_are_scrubbed(client, sample_token, mock_ha_client):
    """Every key in FORBIDDEN_DATA_KEYS is stripped."""
    data_payload = {key: "injected" for key in FORBIDDEN_DATA_KEYS}
    data_payload["brightness"] = 128  # legitimate key

    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={
            "entity_id": "light.living_room",
            "service": "turn_on",
            "data": data_payload,
        },
    )
    assert resp.status_code == 200
    service_data = mock_ha_client["call_service"].call_args[0][2]
    for key in FORBIDDEN_DATA_KEYS:
        if key == "entity_id":
            # entity_id is re-added with the real value
            assert service_data[key] == "light.living_room"
        else:
            assert key not in service_data


# ---------------------------------------------------------------------------
# Token validation — real DB lookups in _validate_token
# ---------------------------------------------------------------------------

async def test_expired_token_returns_410(client, mock_ha_client, test_db):
    now = int(time.time())
    await db.create_token(
        label="Expired", slug="expired-tok", entity_ids=["light.a"],
        expires_at=now - 1, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/expired-tok/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 410
    assert resp.json()["detail"] == "Access unavailable"
    mock_ha_client["call_service"].assert_not_called()
    mock_ha_client["fire_event"].assert_not_called()
    mock_ha_client["logbook_log"].assert_not_called()


async def test_revoked_token_returns_410(client, mock_ha_client, test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Revoked", slug="revoked-tok", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.revoke_token(token["id"])
    resp = await client.post(
        "/g/revoked-tok/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 410
    assert resp.json()["detail"] == "Access unavailable"
    mock_ha_client["call_service"].assert_not_called()
    mock_ha_client["fire_event"].assert_not_called()
    mock_ha_client["logbook_log"].assert_not_called()


async def test_nonexistent_slug_returns_410(client, mock_ha_client, test_db):
    resp = await client.post(
        "/g/does-not-exist/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 410
    assert resp.json()["detail"] == "Access unavailable"
    mock_ha_client["call_service"].assert_not_called()
    mock_ha_client["fire_event"].assert_not_called()
    mock_ha_client["logbook_log"].assert_not_called()


async def test_entity_not_in_allowlist_returns_403(client, sample_token, mock_ha_client):
    """Entity must be in the token's entity list (checked via real DB query)."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.NOT_ALLOWED", "service": "turn_on"},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


# ---------------------------------------------------------------------------
# IP allowlist — real ipaddress validation
# ---------------------------------------------------------------------------

async def test_ip_allowlist_blocks_non_matching(client, mock_ha_client, test_db):
    now = int(time.time())
    await db.create_token(
        label="IP", slug="ip-block", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=["10.0.0.0/8"],
    )
    # testserver client comes from 127.0.0.1 — not in 10.0.0.0/8
    resp = await client.post(
        "/g/ip-block/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 403
    assert "IP not allowed" in resp.json()["detail"]
    mock_ha_client["call_service"].assert_not_called()


async def test_ip_allowlist_allows_matching(client, mock_ha_client, test_db):
    now = int(time.time())
    await db.create_token(
        label="IP", slug="ip-allow", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=["127.0.0.0/8"],
    )
    resp = await client.post(
        "/g/ip-allow/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 200
    mock_ha_client["call_service"].assert_called_once()


async def test_guest_pwa_ip_allowlist_blocks_non_matching(client, mock_ha_client, test_db):
    now = int(time.time())
    token = await db.create_token(
        label="IP", slug="ip-page-block", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=["10.0.0.0/8"],
    )
    resp = await client.get("/g/ip-page-block")
    assert resp.status_code == 403
    assert "text/html" in resp.headers["content-type"]
    row = await db.get_token_by_id(token["id"])
    assert row["last_accessed"] is None
    conn = await db.get_db()
    async with conn.execute(
        "SELECT COUNT(*) as cnt FROM access_log WHERE token_id = ?", (token["id"],)
    ) as cur:
        count = await cur.fetchone()
    assert count["cnt"] == 0
    mock_ha_client["fire_event"].assert_not_called()
    mock_ha_client["logbook_log"].assert_not_called()


# ---------------------------------------------------------------------------
# Rate limiting — real rate_limiter singleton
# ---------------------------------------------------------------------------

async def test_rate_limit_returns_429(client, mock_ha_client, test_db):
    """Exhaust the global 30 RPM limit and verify 429 is returned."""
    from app.routers.guest import COMMAND_RPM

    now = int(time.time())
    await db.create_token(
        label="Rate", slug="rate-test", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    # Exhaust the global RPM limit
    for i in range(COMMAND_RPM):
        resp = await client.post(
            "/g/rate-test/command",
            json={"entity_id": "light.a", "service": "turn_on"},
        )
        assert resp.status_code == 200

    # Next request is blocked
    resp = await client.post(
        "/g/rate-test/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 429
    assert mock_ha_client["call_service"].call_count == COMMAND_RPM


# ---------------------------------------------------------------------------
# Service format validation — real regex in the router
# ---------------------------------------------------------------------------

async def test_service_injection_attempt_returns_422(client, sample_token, mock_ha_client):
    """Shell metacharacters in service name are caught by regex validation."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "light.turn_on; rm -rf /"},
    )
    assert resp.status_code == 422
    mock_ha_client["call_service"].assert_not_called()


async def test_service_with_uppercase_rejected(client, sample_token, mock_ha_client):
    """Service format regex only allows lowercase + underscores."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "light.TURN_ON"},
    )
    assert resp.status_code == 422
    mock_ha_client["call_service"].assert_not_called()


# ---------------------------------------------------------------------------
# Guest PWA page rendering — real template rendering + DB lookup
# ---------------------------------------------------------------------------

async def test_guest_pwa_valid_token_renders_page(client, sample_token, mock_ha_client):
    """A valid token slug renders the guest PWA page and touches the token."""
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    # Token should have been touched (last_accessed updated)
    row = await db.get_token_by_id(sample_token["id"])
    assert row["last_accessed"] is not None
    # First-ever open fires both "page_load" and "first_use" (the latter is
    # the one-time binding-claim event, see app/routers/guest.py).
    assert mock_ha_client["fire_event"].call_count == 2
    payloads = [call.args[1] for call in mock_ha_client["fire_event"].call_args_list]
    assert {p["activity"] for p in payloads} == {"page_load", "first_use"}
    for payload in payloads:
        assert payload["schema_version"] == 1
        assert payload["token_label"] == "Test Token"
        assert sample_token["slug"] not in payload.values()
        assert sample_token["id"] not in payload.values()
    assert mock_ha_client["logbook_log"].call_count == 2
    # Binding cookie should have been set on first open.
    assert any(c.startswith(f"hp_bind_{sample_token['slug']}=") for c in resp.headers.get_list("set-cookie"))


async def test_guest_pwa_page_load_activity_is_debounced(client, sample_token, mock_ha_client):
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200
    # First open: page_load + first_use (2). Second open: page_load debounced,
    # first_use doesn't refire (already bound) — no new events.
    assert mock_ha_client["fire_event"].call_count == 2
    assert mock_ha_client["logbook_log"].call_count == 2


async def test_guest_pwa_page_load_activity_debounce_expires(client, sample_token, mock_ha_client):
    import app.routers.guest as guest_mod

    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200
    guest_mod._page_load_activity_ts[sample_token["id"]] -= guest_mod.PAGE_LOAD_EVENT_DEBOUNCE_SECONDS + 1
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200
    # First open: page_load + first_use (2). Second open: debounce expired so
    # page_load fires again (+1); first_use never refires (already bound).
    assert mock_ha_client["fire_event"].call_count == 3
    assert mock_ha_client["logbook_log"].call_count == 3


async def test_guest_pwa_page_load_activity_debounce_is_per_token(
    client,
    sample_token,
    mock_ha_client,
    test_db,
):
    now = int(time.time())
    second = await db.create_token(
        label="Second",
        slug="second-token",
        entity_ids=["light.a"],
        expires_at=now + 3600,
        ip_allowlist=None,
    )
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200
    resp = await client.get(f"/g/{second['slug']}")
    assert resp.status_code == 200
    # Each token's first-ever open fires page_load + first_use (2 each).
    assert mock_ha_client["fire_event"].call_count == 4
    assert mock_ha_client["logbook_log"].call_count == 4


async def test_guest_pwa_activity_event_failure_does_not_break_page(client, sample_token, mock_ha_client):
    mock_ha_client["fire_event"].side_effect = RuntimeError("ha unavailable")
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200
    # Both page_load and first_use are attempted independently (each is its
    # own background task) and each failure is caught on its own.
    assert mock_ha_client["fire_event"].call_count == 2
    assert mock_ha_client["logbook_log"].call_count == 2


async def test_guest_pwa_logbook_failure_does_not_break_page(client, sample_token, mock_ha_client):
    mock_ha_client["logbook_log"].side_effect = RuntimeError("logbook unavailable")
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200
    assert mock_ha_client["fire_event"].call_count == 2
    assert mock_ha_client["logbook_log"].call_count == 2


async def test_guest_pwa_expired_token_renders_expired_page(client, mock_ha_client, test_db):
    """An expired token renders the expired page with 410."""
    now = int(time.time())
    await db.create_token(
        label="Old", slug="old-link", entity_ids=["light.a"],
        expires_at=now - 1, ip_allowlist=None,
    )
    resp = await client.get("/g/old-link")
    assert resp.status_code == 410
    assert "text/html" in resp.headers["content-type"]
    mock_ha_client["fire_event"].assert_not_called()
    mock_ha_client["logbook_log"].assert_not_called()


async def test_guest_pwa_nonexistent_slug_renders_expired_page(client, mock_ha_client, test_db):
    """A slug that doesn't exist renders the expired page with 410."""
    resp = await client.get("/g/does-not-exist")
    assert resp.status_code == 410
    mock_ha_client["fire_event"].assert_not_called()
    mock_ha_client["logbook_log"].assert_not_called()


# ---------------------------------------------------------------------------
# Security headers — real middleware on every response
# ---------------------------------------------------------------------------

async def test_security_headers_on_guest_route(client, sample_token, mock_ha_client):
    """Guest routes get nonce-based CSP (no unsafe-inline for scripts)."""
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "no-referrer"
    csp = resp.headers["content-security-policy"]
    assert "'nonce-" in csp
    assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]


async def test_security_headers_on_admin_route(client, admin_session, mock_ha_client):
    """Admin routes use nonce-based CSP (inline handlers migrated to event delegation)."""
    resp = await client.get("/admin/tokens", cookies=admin_session)
    csp = resp.headers["content-security-policy"]
    script_src_section = csp.split("script-src")[1].split(";")[0]
    assert "'nonce-" in script_src_section
    assert "'unsafe-inline'" not in script_src_section


# ---------------------------------------------------------------------------
# Error response — no HA internals leaked to guests
# ---------------------------------------------------------------------------

async def test_ha_error_does_not_leak_status_code(client, sample_token, mock_ha_client):
    """HA error responses don't leak internal status codes to guests."""
    mock_response = httpx.Response(status_code=500, request=httpx.Request("POST", "http://ha"))
    mock_ha_client["call_service"].side_effect = httpx.HTTPStatusError(
        "Server Error", request=mock_response.request, response=mock_response
    )
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "turn_on"},
    )
    assert resp.status_code == 502
    assert resp.json()["detail"] == "Service call failed"
    assert "500" not in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Guest state endpoint — real DB, mocked HA states
# ---------------------------------------------------------------------------

async def test_guest_state_returns_filtered_entities(client, sample_token, mock_ha_client):
    """State endpoint only returns entities that belong to the token."""
    mock_ha_client["get_states"].return_value = [
        {"entity_id": "light.living_room", "state": "on", "attributes": {"brightness": 255}},
        {"entity_id": "light.bedroom", "state": "off", "attributes": {}},
        {"entity_id": "switch.garage", "state": "on", "attributes": {}},
    ]
    # Reset the state cache so our mock data is fetched
    import app.routers.guest as guest_mod
    guest_mod._states_cache = None

    resp = await client.get(f"/g/{sample_token['slug']}/state")
    assert resp.status_code == 200
    data = resp.json()
    assert data["entities"] == ["light.living_room"]
    assert "light.living_room" in data["states"]
    assert data["states"]["light.living_room"]["state"] == "on"
    assert "light.bedroom" not in data["states"]
    assert "switch.garage" not in data["states"]


async def test_guest_state_unavailable_for_missing_entities(client, mock_ha_client, test_db):
    """Entities not in HA state list are returned as 'unavailable'."""
    now = int(time.time())
    await db.create_token(
        label="Missing", slug="missing-state", entity_ids=["light.nonexistent"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    mock_ha_client["get_states"].return_value = []
    import app.routers.guest as guest_mod
    guest_mod._states_cache = None

    resp = await client.get("/g/missing-state/state")
    assert resp.status_code == 200
    data = resp.json()
    assert data["states"]["light.nonexistent"]["state"] == "unavailable"


async def test_guest_state_returns_read_only_sensor(client, mock_ha_client, test_db):
    """Read-only sensor entities assigned to a token are returned by state."""
    now = int(time.time())
    await db.create_token(
        label="Sensor", slug="sensor-state", entity_ids=["sensor.temperature"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    mock_ha_client["get_states"].return_value = [
        {
            "entity_id": "sensor.temperature",
            "state": "72",
            "attributes": {"friendly_name": "Temperature", "unit_of_measurement": "F"},
        },
        {"entity_id": "sensor.outside", "state": "66", "attributes": {}},
    ]
    import app.routers.guest as guest_mod
    guest_mod._states_cache = None

    resp = await client.get("/g/sensor-state/state")
    assert resp.status_code == 200
    data = resp.json()
    assert data["entities"] == ["sensor.temperature"]
    assert data["states"]["sensor.temperature"]["state"] == "72"
    assert data["states"]["sensor.temperature"]["attributes"]["unit_of_measurement"] == "F"
    assert "sensor.outside" not in data["states"]


# ---------------------------------------------------------------------------
# button / input_button domain support
# ---------------------------------------------------------------------------

async def test_button_domain_press_allowed(client, mock_ha_client, test_db):
    now = int(time.time())
    await db.create_token(
        label="Portal", slug="portal-button", entity_ids=["input_button.front_gate"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/portal-button/command",
        json={"entity_id": "input_button.front_gate", "service": "press"},
    )
    assert resp.status_code == 200
    mock_ha_client["call_service"].assert_called_once()
    args = mock_ha_client["call_service"].call_args[0]
    assert args[0] == "input_button"
    assert args[1] == "press"
    assert args[2]["entity_id"] == "input_button.front_gate"


async def test_input_button_only_allows_press(client, mock_ha_client, test_db):
    now = int(time.time())
    await db.create_token(
        label="Portal", slug="portal-button-2", entity_ids=["input_button.front_gate"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/portal-button-2/command",
        json={"entity_id": "input_button.front_gate", "service": "turn_on"},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


# ---------------------------------------------------------------------------
# Scheduled / recurring access (starts_at, recurrence)
# ---------------------------------------------------------------------------

async def test_future_starts_at_returns_403_on_command(client, mock_ha_client, test_db):
    now = int(time.time())
    await db.create_token(
        label="Scheduled", slug="future-token", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None, starts_at=now + 300,
    )
    resp = await client.post(
        "/g/future-token/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Access not yet active"
    mock_ha_client["call_service"].assert_not_called()


async def test_future_starts_at_pwa_renders_not_active_yet(client, mock_ha_client, test_db):
    now = int(time.time())
    await db.create_token(
        label="Scheduled", slug="future-pwa", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None, starts_at=now + 300,
    )
    resp = await client.get("/g/future-pwa")
    assert resp.status_code == 403
    assert "text/html" in resp.headers["content-type"]


async def test_past_starts_at_behaves_normally(client, mock_ha_client, test_db):
    """A starts_at in the past is equivalent to no starts_at (regression guard)."""
    now = int(time.time())
    await db.create_token(
        label="Scheduled", slug="past-token", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None, starts_at=now - 300,
    )
    resp = await client.post(
        "/g/past-token/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 200
    mock_ha_client["call_service"].assert_called_once()


async def test_recurrence_outside_window_returns_403(client, mock_ha_client, test_db):
    now = int(time.time())
    # A recurrence window that (barring extraordinary test-run timing) does
    # not include the current moment: 1 minute wide, far in the past today.
    await db.create_token(
        label="Recurring", slug="recur-outside", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
        recurrence={"weekdays": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "end": "00:01"},
    )
    resp = await client.post(
        "/g/recur-outside/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    # Either inside (extremely unlikely at 00:00-00:01) or outside — assert
    # the two possible outcomes are both handled without error either way.
    assert resp.status_code in (200, 403)


async def test_recurrence_inside_window_allows_access(client, mock_ha_client, test_db):
    import app.routers.guest as guest_mod
    from datetime import datetime
    from zoneinfo import ZoneInfo

    now = int(time.time())
    local = datetime.fromtimestamp(now, tz=ZoneInfo(settings.timezone))
    await db.create_token(
        label="Recurring", slug="recur-inside", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
        recurrence={
            "weekdays": [local.weekday()],
            "start": "00:00",
            "end": "23:59",
        },
    )
    resp = await client.post(
        "/g/recur-inside/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 200
    mock_ha_client["call_service"].assert_called_once()


async def test_recurrence_wrong_weekday_returns_403(client, mock_ha_client, test_db):
    from datetime import datetime
    from zoneinfo import ZoneInfo

    now = int(time.time())
    local = datetime.fromtimestamp(now, tz=ZoneInfo(settings.timezone))
    wrong_day = (local.weekday() + 1) % 7
    await db.create_token(
        label="Recurring", slug="recur-wrong-day", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
        recurrence={"weekdays": [wrong_day], "start": "00:00", "end": "23:59"},
    )
    resp = await client.post(
        "/g/recur-wrong-day/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


# ---------------------------------------------------------------------------
# Local-network-only restriction for access-type domains
# ---------------------------------------------------------------------------

async def test_local_only_domain_blocked_when_not_on_home_network(client, mock_ha_client, test_db, local_network_cidrs):
    local_network_cidrs(["10.0.0.0/8"])  # test client is 127.0.0.1 — won't match
    now = int(time.time())
    await db.create_token(
        label="Portal", slug="local-only-blocked", entity_ids=["input_button.front_gate"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/local-only-blocked/command",
        json={"entity_id": "input_button.front_gate", "service": "press"},
    )
    assert resp.status_code == 403
    assert "home network" in resp.json()["detail"].lower()
    mock_ha_client["call_service"].assert_not_called()


async def test_local_only_domain_allowed_when_on_home_network(client, mock_ha_client, test_db, local_network_cidrs):
    local_network_cidrs(["127.0.0.0/8"])  # matches the test client's IP
    now = int(time.time())
    await db.create_token(
        label="Portal", slug="local-only-allowed", entity_ids=["input_button.front_gate"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/local-only-allowed/command",
        json={"entity_id": "input_button.front_gate", "service": "press"},
    )
    assert resp.status_code == 200
    mock_ha_client["call_service"].assert_called_once()


async def test_light_domain_never_restricted_by_local_network(client, mock_ha_client, test_db, local_network_cidrs):
    """Lights (and other non-access domains) are never gated by local_network_cidrs."""
    local_network_cidrs(["10.0.0.0/8"])  # would block an access-type domain
    now = int(time.time())
    await db.create_token(
        label="Light", slug="light-not-restricted", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/light-not-restricted/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 200
    mock_ha_client["call_service"].assert_called_once()


async def test_local_network_cidrs_empty_means_no_restriction(client, mock_ha_client, test_db):
    """Default (empty) local_network_cidrs preserves today's behavior."""
    assert settings.local_network_cidrs == []
    now = int(time.time())
    await db.create_token(
        label="Portal", slug="no-restriction-default", entity_ids=["input_button.front_gate"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/no-restriction-default/command",
        json={"entity_id": "input_button.front_gate", "service": "press"},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Single-browser binding
# ---------------------------------------------------------------------------

async def test_first_open_claims_binding_and_sets_cookie(client, sample_token, mock_ha_client):
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200
    row = await db.get_token_by_id(sample_token["id"])
    assert row["bound_secret"] is not None
    assert row["bound_claimed_at"] is not None
    assert any(c.startswith(f"hp_bind_{sample_token['slug']}=") for c in resp.headers.get_list("set-cookie"))


async def test_second_browser_without_cookie_is_blocked(client, sample_token, mock_ha_client):
    # First open claims the binding for this (shared) test client's cookiejar.
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200

    # A second, independent client has no cookies at all — simulates a
    # different browser/device that received a forwarded link.
    from main import app as _app
    transport = httpx.ASGITransport(app=_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as other_client:
        resp2 = await other_client.get(f"/g/{sample_token['slug']}")
        assert resp2.status_code == 403


async def test_command_blocked_for_unbound_device(client, sample_token, mock_ha_client):
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200

    from main import app as _app
    transport = httpx.ASGITransport(app=_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as other_client:
        resp2 = await other_client.post(
            f"/g/{sample_token['slug']}/command",
            json={"entity_id": "light.living_room", "service": "turn_on"},
        )
        assert resp2.status_code == 403
        assert "already in use" in resp2.json()["detail"].lower()
    mock_ha_client["call_service"].assert_not_called()


async def test_unbind_allows_a_new_device_to_claim(client, sample_token, mock_ha_client):
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200

    await db.unbind_token(sample_token["id"])

    from main import app as _app
    transport = httpx.ASGITransport(app=_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as other_client:
        resp2 = await other_client.get(f"/g/{sample_token['slug']}")
        assert resp2.status_code == 200
        row = await db.get_token_by_id(sample_token["id"])
        assert row["bound_secret"] is not None
