"""Who is really on the other end of a request.

Behind a reverse proxy the TCP peer is the proxy, and the visitor's address
travels in X-Forwarded-For. That header is a list the client starts and every
proxy *appends* to (nginx's ``$proxy_add_x_forwarded_for``, which is what
Nginx Proxy Manager sends), so only the right-hand end is trustworthy: the
left-hand values are whatever the visitor chose to write.

Reading the first value — what this module replaces — let any guest with a
valid link claim to be on the home network, or in an allowed country, by
sending ``X-Forwarded-For: 192.168.1.10`` themselves.

The rule here is the standard one: believe X-Forwarded-For only when the peer
is a trusted proxy, and walk it from the right, skipping hops that are
themselves trusted proxies. The first address that is not a trusted proxy is
the client.
"""

from __future__ import annotations

import ipaddress

from fastapi import Request

from app.config import settings


def _parse(value: str):
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _is_trusted(addr, cidrs: list[str]) -> bool:
    if addr is None:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def client_ip(request: Request) -> str:
    """The visitor's IP, or "unknown" when there is none to give."""
    peer = request.client.host if request.client else ""
    peer_addr = _parse(peer)
    if peer_addr is None:
        return "unknown"

    trusted = settings.trusted_proxies
    forwarded = request.headers.get("X-Forwarded-For", "")
    if not forwarded or not _is_trusted(peer_addr, trusted):
        # Straight from the visitor (or from a proxy nobody vouched for): the
        # header is theirs to invent, so it is ignored.
        return str(peer_addr)

    hops = [h.strip() for h in forwarded.split(",") if h.strip()]
    for hop in reversed(hops):
        addr = _parse(hop)
        if addr is None:
            # Garbage where a trusted proxy should have written an address:
            # nothing to the left of it can be trusted either. "unknown" fails
            # closed on every allowlist.
            return "unknown"
        if not _is_trusted(addr, trusted):
            return str(addr)
    # Every hop is a trusted proxy (e.g. a guest on the LAN reaching the
    # proxy by its private address): the left-most one is the visitor.
    first = _parse(hops[0]) if hops else None
    return str(first) if first is not None else str(peer_addr)
