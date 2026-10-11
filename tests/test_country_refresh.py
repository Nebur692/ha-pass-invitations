"""Links restricted by country follow the country's current IP ranges."""
import json
import time
from unittest.mock import AsyncMock

import httpx
import pytest

from app import database as db
from app import geoip

OLD = ["198.51.100.0/24"]
NEW = ["198.51.100.0/24", "203.0.113.0/24"]  # the country gained a block


@pytest.fixture
def ranges(monkeypatch):
    """What ipdeny (through the cache) says each country holds today."""
    today = {"es": NEW, "pt": ["192.0.2.0/24"]}

    async def _cidrs(code):
        cc = code.lower()
        if cc not in today:
            raise geoip.CountryResolutionError(f"no ranges for {code}")
        return today[cc]

    fake = AsyncMock(side_effect=_cidrs)
    monkeypatch.setattr(geoip, "get_country_cidrs", fake)
    return today


async def _token(slug, countries, ip_allowlist, **extra):
    return await db.create_token(
        label=slug,
        slug=slug,
        entity_ids=["light.hall"],
        expires_at=extra.pop("expires_at", int(time.time()) + 3600),
        ip_allowlist=ip_allowlist,
        country_allowlist=countries,
        **extra,
    )


async def _stored(token):
    row = await db.get_token_by_id(token["id"])
    return json.loads(row["ip_allowlist"]) if row["ip_allowlist"] else None


async def test_a_token_gets_its_countrys_new_ranges(test_db, ranges):
    token = await _token("spain", ["ES"], OLD)

    assert await geoip.refresh_token_allowlists() == 1
    assert sorted(await _stored(token)) == sorted(NEW)


async def test_nothing_is_written_when_nothing_changed(test_db, ranges):
    token = await _token("spain", ["ES"], NEW)

    assert await geoip.refresh_token_allowlists() == 0
    assert sorted(await _stored(token)) == sorted(NEW)


async def test_several_countries_are_combined(test_db, ranges):
    token = await _token("iberia", ["ES", "PT"], OLD)

    await geoip.refresh_token_allowlists()

    assert sorted(await _stored(token)) == sorted(NEW + ["192.0.2.0/24"])


async def test_a_country_that_cannot_be_resolved_keeps_the_old_list(test_db, ranges):
    broken = await _token("nowhere", ["ES", "FR"], OLD)  # FR has no ranges today
    fine = await _token("spain", ["ES"], OLD)

    assert await geoip.refresh_token_allowlists() == 1
    assert await _stored(broken) == OLD
    assert sorted(await _stored(fine)) == sorted(NEW)


async def test_tokens_without_countries_are_left_alone(test_db, ranges):
    hand_written = await _token("cidrs", None, ["10.0.0.0/8"])
    open_link = await _token("open", None, None)

    assert await geoip.refresh_token_allowlists() == 0
    assert await _stored(hand_written) == ["10.0.0.0/8"]
    assert await _stored(open_link) is None
    geoip.get_country_cidrs.assert_not_called()


async def test_expired_and_revoked_tokens_are_refreshed_too(test_db, ranges):
    """They can be renewed with the same settings, and should come back with
    today's ranges."""
    expired = await _token("expired", ["ES"], OLD, expires_at=int(time.time()) - 60)
    revoked = await _token("revoked", ["ES"], OLD)
    await db.revoke_token(revoked["id"])

    assert await geoip.refresh_token_allowlists() == 2
    assert sorted(await _stored(expired)) == sorted(NEW)
    assert sorted(await _stored(revoked)) == sorted(NEW)


async def test_a_guest_in_the_new_block_gets_in_after_the_refresh(test_db, mock_ha_client, ranges):
    """End to end: the refreshed list is the one the guest page enforces."""
    from main import app

    token = await _token("spain", ["ES"], OLD)
    transport = httpx.ASGITransport(app=app, client=("203.0.113.9", 4321))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as guest:
        before = await guest.get(f"/g/{token['slug']}/state")
        await geoip.refresh_token_allowlists()
        after = await guest.get(f"/g/{token['slug']}/state")

    assert before.status_code == 403
    assert after.status_code == 200


async def test_the_app_runs_the_refresh_on_its_own(test_db, mock_ha_client, monkeypatch):
    """Written is not wired: starting the app is what schedules it."""
    import asyncio

    from main import app, lifespan

    refresh = AsyncMock(return_value=0)
    monkeypatch.setattr(geoip, "refresh_token_allowlists", refresh)
    monkeypatch.setattr(geoip, "TOKEN_REFRESH_FIRST_DELAY_SECONDS", 0)
    monkeypatch.setattr(geoip, "TOKEN_REFRESH_INTERVAL_SECONDS", 3600)

    async with lifespan(app):
        for _ in range(50):
            if refresh.await_count:
                break
            await asyncio.sleep(0.01)

    assert refresh.await_count == 1
