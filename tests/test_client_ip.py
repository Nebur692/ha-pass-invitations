"""Which address is the guest's — and that a guest cannot choose it.

Nginx Proxy Manager (like any nginx with $proxy_add_x_forwarded_for) appends
the address it saw to whatever X-Forwarded-For the visitor sent. So the
visitor controls everything except the right-hand end.
"""
import time

import httpx
import pytest
from starlette.requests import Request

from app import database as db
from app.client_ip import client_ip
from app.config import settings

PROXY = "192.168.100.22"  # where NPM sits on the author's network
GUEST = "203.0.113.7"     # a guest on mobile data


def _request(peer, forwarded=None):
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded is not None else []
    scope = {"type": "http", "headers": headers, "client": (peer, 1234) if peer else None}
    return Request(scope)


def test_behind_the_proxy_the_guest_is_who_the_proxy_saw():
    assert client_ip(_request(PROXY, GUEST)) == GUEST


def test_a_guest_cannot_claim_a_home_address_through_the_proxy():
    """The bypass: the guest sends a LAN address and the proxy appends theirs."""
    assert client_ip(_request(PROXY, f"192.168.1.10, {GUEST}")) == GUEST


def test_a_guest_cannot_claim_anything_reaching_the_app_directly():
    """No proxy in between: the header is the visitor's own text."""
    assert client_ip(_request(GUEST, "192.168.1.10")) == GUEST


def test_a_guest_on_the_home_wifi_through_the_proxy_is_on_the_home_wifi():
    """Every hop is private, so the left-most is the guest — same as before."""
    assert client_ip(_request(PROXY, "192.168.15.27")) == "192.168.15.27"


def test_two_proxies_in_a_row():
    assert client_ip(_request(PROXY, f"1.2.3.4, {GUEST}, 10.0.0.5")) == GUEST


def test_no_header_is_the_peer():
    assert client_ip(_request(PROXY)) == PROXY
    assert client_ip(_request(GUEST)) == GUEST


def test_garbage_where_the_proxy_writes_fails_closed():
    assert client_ip(_request(PROXY, f"{GUEST}, not-an-ip")) == "unknown"


def test_no_peer_is_unknown():
    assert client_ip(_request(None, GUEST)) == "unknown"


def test_ipv6_guest():
    assert client_ip(_request(PROXY, "fd00::1, 2001:db8::7")) == "2001:db8::7"


def test_narrowed_to_the_one_proxy(monkeypatch):
    """With only NPM trusted, the right-most address that is not NPM wins —
    even a private one, because nothing else vouches for what is left of it."""
    monkeypatch.setattr(settings, "trusted_proxies", [f"{PROXY}/32"])
    assert client_ip(_request(PROXY, "192.168.1.10, 192.168.15.3")) == "192.168.15.3"
    assert client_ip(_request("192.168.15.3", GUEST)) == "192.168.15.3"


# ---------------------------------------------------------------------------
# End to end: the gates that read the IP
# ---------------------------------------------------------------------------

@pytest.fixture
async def through_proxy(test_db, mock_ha_client):
    """An HTTP client whose TCP peer is the proxy, as in production."""
    from main import app

    transport = httpx.ASGITransport(app=app, client=(PROXY, 4321))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


async def _lock_token(**extra):
    return await db.create_token(
        label="Front door",
        slug="front-door",
        entity_ids=["lock.front_door"],
        expires_at=int(time.time()) + 3600,
        **extra,
    )


async def test_a_lock_is_not_opened_from_outside_by_faking_a_home_address(
    through_proxy, mock_ha_client
):
    settings.local_network_cidrs = ["192.168.0.0/16"]
    token = await _lock_token(ip_allowlist=None)

    resp = await through_proxy.post(
        f"/g/{token['slug']}/command",
        json={"entity_id": "lock.front_door", "service": "unlock"},
        headers={"X-Forwarded-For": f"192.168.1.10, {GUEST}"},
    )

    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


async def test_the_same_lock_opens_from_the_home_wifi(through_proxy, mock_ha_client):
    settings.local_network_cidrs = ["192.168.0.0/16"]
    token = await _lock_token(ip_allowlist=None)

    resp = await through_proxy.post(
        f"/g/{token['slug']}/command",
        json={"entity_id": "lock.front_door", "service": "unlock"},
        headers={"X-Forwarded-For": "192.168.15.27"},
    )

    assert resp.status_code == 200
    mock_ha_client["call_service"].assert_called_once()


async def test_the_link_allowlist_cannot_be_dodged_either(through_proxy, mock_ha_client):
    """The country allowlist is stored as CIDRs here, so this covers it too."""
    token = await _lock_token(ip_allowlist=["198.51.100.0/24"])

    faked = await through_proxy.get(
        f"/g/{token['slug']}/state",
        headers={"X-Forwarded-For": f"198.51.100.9, {GUEST}"},
    )
    real = await through_proxy.get(
        f"/g/{token['slug']}/state",
        headers={"X-Forwarded-For": "198.51.100.9"},
    )

    assert faked.status_code == 403
    assert real.status_code != 403
