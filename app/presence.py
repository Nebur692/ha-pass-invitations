"""Proofs that the guest is physically present, verified by the server.

The threat model is what shapes this whole module: the adversary is the guest
themselves. They hold a valid link, so any proof their own phone merely
*asserts* is worthless — they can patch the app and lie. Every provider here
therefore derives its answer from something the *server* observes.

Modes:

``local_network``
    The original mechanism. The reverse proxy tells us the source IP; the guest
    cannot forge it. Requires handing out the WiFi password, which is the thing
    the Android app exists to avoid.

``ha_ble``
    The Android app advertises over Bluetooth; the Bluetooth scanners already
    wired into Home Assistant (Shelly Gen2+, ESPHome proxies, a local adapter)
    hear it, and Home Assistant streams every advertisement to us over the
    WebSocket connection we already hold. The observation is made by the
    admin's own hardware and delivered over the admin's own Home Assistant —
    the guest's phone is never asked to vouch for itself.

    The advertised value is a single 128-bit service UUID: a fixed 96-bit
    HAPass prefix plus a 32-bit code. The code is *not* a static device id —
    that would be copyable, and a EUR 5 board hidden by the door replaying it
    would open the lock forever. It is instead derived from the token's binding
    secret and the current 15-second window, so a captured code is worthless
    within half a minute.

What this cannot do is prove that the *phone* is at the door rather than some
radio the guest left there and feeds over the internet. No cryptography inside
a phone can: that is distance bounding, and it needs the physical layer (UWB
time-of-flight). See the plan's "límites honestos" section.
"""
import asyncio
import hashlib
import hmac
import ipaddress
import logging
import struct
import time

from app import database as db
from app.config import VALID_PRESENCE_MODES, settings

logger = logging.getLogger(__name__)

VALID_MODES = VALID_PRESENCE_MODES

# 96 bits of fixed prefix; the remaining 32 bits carry the rotating code.
# Formatted as a UUID string, that is the first 24 hex digits, with the code
# occupying the last 8 of the final group.
UUID_PREFIX = "48415041-5353-4c4b-0001-0000"

# The rotating code changes every window. Short enough that a captured value
# expires quickly, long enough to absorb ordinary clock skew at +/- 1 window.
CODE_WINDOW_SECONDS = 15
CODE_WINDOW_SLACK = 1

# How long the (token_id, bound_secret) list is reused before re-reading it.
# Only ever consulted when a HAPass advertisement is actually in the air.
TOKEN_CACHE_TTL_SECONDS = 60

# Per token, how many recent sightings to keep. Enough for the admin panel's
# "find the door" calibration step to show a stable picture.
MAX_OBSERVATIONS_PER_TOKEN = 20


class PresenceDenied(Exception):
    """Raised when the configured proofs are not satisfied."""

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


# ---------------------------------------------------------------------------
# Rotating code
# ---------------------------------------------------------------------------

def code_for(secret: str, window: int) -> str:
    """The 8 hex digits an app holding `secret` advertises during `window`."""
    mac = hmac.new(secret.encode("utf-8"), struct.pack(">Q", window), hashlib.sha256)
    return mac.digest()[:4].hex()


def current_window(now: float | None = None) -> int:
    return int((now if now is not None else time.time()) // CODE_WINDOW_SECONDS)


def uuid_for(secret: str, window: int) -> str:
    """Full service UUID an app advertises — used by tests and the admin QR."""
    return UUID_PREFIX + code_for(secret, window)


def extract_code(service_uuid: str) -> str | None:
    """The rotating code out of an advertised UUID, or None if not ours."""
    uuid = service_uuid.lower()
    if not uuid.startswith(UUID_PREFIX):
        return None
    code = uuid[len(UUID_PREFIX):]
    return code if len(code) == 8 else None


# ---------------------------------------------------------------------------
# Observation store — fed by the Home Assistant Bluetooth subscription
# ---------------------------------------------------------------------------
# token_id -> list of {"ts", "source", "rssi"}, newest last.
_observations: dict[str, list[dict]] = {}

_token_secrets: list[tuple[str, str]] = []
_token_secrets_at: float = 0.0
_code_table: dict[str, str] = {}
_code_table_windows: tuple[int, ...] = ()
_lock = asyncio.Lock()


async def _refresh_token_secrets(now: float) -> None:
    global _token_secrets, _token_secrets_at
    if _token_secrets_at and now - _token_secrets_at < TOKEN_CACHE_TTL_SECONDS:
        return
    _token_secrets = await db.list_bound_token_secrets()
    _token_secrets_at = now


def _rebuild_code_table(windows: tuple[int, ...]) -> None:
    """Codes every currently-bound token would advertise in these windows."""
    global _code_table, _code_table_windows
    table: dict[str, str] = {}
    for token_id, secret in _token_secrets:
        for window in windows:
            table[code_for(secret, window)] = token_id
    _code_table = table
    _code_table_windows = windows


async def record_advertisement(service_uuids: list[str], source: str, rssi: int) -> str | None:
    """Note a Bluetooth advertisement relayed by Home Assistant.

    Cheap on the hot path: everything below the prefix check only runs when a
    HAPass app is genuinely advertising nearby, which is rare.
    """
    codes = [c for c in (extract_code(u) for u in service_uuids) if c]
    if not codes:
        return None

    now = time.time()
    window = current_window(now)
    windows = tuple(range(window - CODE_WINDOW_SLACK, window + CODE_WINDOW_SLACK + 1))

    async with _lock:
        await _refresh_token_secrets(now)
        if windows != _code_table_windows:
            _rebuild_code_table(windows)
        token_id = next((_code_table[c] for c in codes if c in _code_table), None)
        if token_id is None:
            return None
        seen = _observations.setdefault(token_id, [])
        seen.append({"ts": now, "source": (source or "").upper(), "rssi": rssi})
        del seen[:-MAX_OBSERVATIONS_PER_TOKEN]
    return token_id


async def recent_observations(token_id: str, max_age: float | None = None) -> list[dict]:
    """Sightings of a token's app, newest last. Used by checks and calibration."""
    cutoff = time.time() - (max_age if max_age is not None else settings.ble_max_age_seconds)
    async with _lock:
        return [o for o in _observations.get(token_id, []) if o["ts"] >= cutoff]


async def reset_state() -> None:
    """Drop every cache. For tests, and after a WebSocket reconnect."""
    global _token_secrets, _token_secrets_at, _code_table, _code_table_windows
    async with _lock:
        _observations.clear()
        _token_secrets = []
        _token_secrets_at = 0.0
        _code_table = {}
        _code_table_windows = ()


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------

def _ip_in_cidrs(client_ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(cidr, strict=False) for cidr in cidrs)


def _check_local_network(client_ip: str) -> None:
    if not settings.local_network_cidrs:
        return  # unconfigured: no restriction, exactly as before
    if not _ip_in_cidrs(client_ip, settings.local_network_cidrs):
        raise PresenceDenied(
            "not_on_local_network",
            "This action is only available while connected to the home network",
        )


async def _check_ha_ble(token_id: str) -> None:
    # Fail closed rather than accept a sighting from any scanner in the house:
    # "somewhere indoors" is not "at the door", and silently accepting it would
    # be exactly the kind of proof-in-name-only this module exists to avoid.
    if not settings.ble_scanners:
        raise PresenceDenied(
            "ble_not_configured",
            "Bluetooth presence is enabled but no door scanner has been selected",
        )

    seen = await recent_observations(token_id)
    if not seen:
        raise PresenceDenied(
            "ble_not_seen",
            "Open the app next to the door — your device was not detected",
        )

    approved = {s.upper() for s in settings.ble_scanners}
    at_door = [o for o in seen if o["source"] in approved]
    if not at_door:
        raise PresenceDenied(
            "ble_wrong_scanner",
            "Your device was detected, but not at the door",
        )
    if not any(o["rssi"] >= settings.ble_min_rssi for o in at_door):
        raise PresenceDenied(
            "ble_too_far",
            "Your device was detected near the door, but too far away",
        )


async def check(token_id: str, client_ip: str) -> None:
    """Enforce the configured presence policy. Raises PresenceDenied."""
    modes = settings.presence_modes
    if not modes:
        return

    failures: list[PresenceDenied] = []
    for mode in modes:
        try:
            if mode == "local_network":
                _check_local_network(client_ip)
            elif mode == "ha_ble":
                await _check_ha_ble(token_id)
        except PresenceDenied as denied:
            failures.append(denied)

    if settings.presence_policy == "all":
        if failures:
            raise failures[0]
        return

    # "any": satisfied unless every configured mode failed.
    if len(failures) == len(modes):
        raise failures[0]
