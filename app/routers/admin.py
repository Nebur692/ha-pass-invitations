"""Admin API router."""
import ipaddress
import json
import logging
import re
import secrets
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from app import database as db
from app.auth import INGRESS_SENTINEL, SESSION_COOKIE, require_admin, verify_password
from app.config import settings
from app import geoip
from app import ha_client
from app import i18n
from app import presence
from app.models import (
    ACCESS_DOMAINS,
    ACCESS_KEYWORDS,
    AdminLanguageRequest,
    AdminLoginRequest,
    EXCLUDE_ACCESS_KEYWORDS,
    EXCLUDE_LIGHT_KEYWORDS,
    LIGHT_DOMAINS,
    LIGHT_KEYWORDS,
    NEVER_EXPIRES_SECONDS,
    SUPPORTED_DOMAINS,
    TokenCreateRequest,
    TokenUpdateEntitiesRequest,
    TokenUpdateExpiryRequest,
    TokenUpdateScheduleRequest,
)
from app.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin")

# Admin session lifetime — 24 hours, hardcoded like Uptime Kuma / Dockge.
ADMIN_SESSION_TTL = 86400

# CSRF: Admin routes are protected by SameSite=strict cookie. The slug-based
# guest auth acts as a bearer token — no additional CSRF token needed.

# M-24: Rate limiting on admin login (5 failed attempts/min/IP)
_login_limiter = RateLimiter()

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@router.post("/login")
async def login(body: AdminLoginRequest, request: Request, response: Response) -> dict:
    if not settings.admin_password:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Login disabled — use HA sidebar")

    # Rate limit login attempts by IP
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    allowed = await _login_limiter.check(f"login:{client_ip}", 5)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts")

    if body.username != settings.admin_username or not await verify_password(body.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    is_https = (
        request.url.scheme == "https"
        or forwarded_proto == "https"
    )
    session_id = await db.create_admin_session(ttl_seconds=ADMIN_SESSION_TTL)
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        samesite="strict",
        secure=is_https,
        max_age=ADMIN_SESSION_TTL,
    )
    return {"ok": True}


@router.post("/logout")
async def logout(response: Response, session_id: str = Depends(require_admin)) -> dict:
    if session_id == INGRESS_SENTINEL:
        return {"ok": True}
    await db.delete_admin_session(session_id)
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Admin profile
# ---------------------------------------------------------------------------

# Cookie persists the manual language override for ~1 year — "auto" clears it.
ADMIN_LANG_COOKIE_MAX_AGE = 31536000


@router.post("/profile/language")
async def set_admin_language(
    body: AdminLanguageRequest,
    request: Request,
    response: Response,
    _: str = Depends(require_admin),
) -> dict:
    if body.language == "auto":
        response.delete_cookie(i18n.ADMIN_LANG_COOKIE)
        resolved = i18n.detect_lang(request.headers.get("accept-language"), i18n.ADMIN_SUPPORTED_LANGS)
    else:
        forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
        is_https = request.url.scheme == "https" or forwarded_proto == "https"
        response.set_cookie(
            i18n.ADMIN_LANG_COOKIE,
            body.language,
            httponly=True,
            samesite="strict",
            secure=is_https,
            max_age=ADMIN_LANG_COOKIE_MAX_AGE,
        )
        resolved = body.language
    return {"ok": True, "language": resolved}


# ---------------------------------------------------------------------------
# Token management
# ---------------------------------------------------------------------------

def _row_to_response(row: Any, entity_ids: list[str] | None = None) -> dict:
    ip_raw = row["ip_allowlist"]
    ip_list = json.loads(ip_raw) if ip_raw else None
    country_raw = row["country_allowlist"] if "country_allowlist" in row.keys() else None
    country_list = json.loads(country_raw) if country_raw else None
    recurrence_raw = row["recurrence"] if "recurrence" in row.keys() else None
    recurrence = json.loads(recurrence_raw) if recurrence_raw else None
    if entity_ids is not None:
        count = len(entity_ids)
    elif "entity_count" in row.keys():
        count = row["entity_count"]
    else:
        count = 0
    return {
        "id": row["id"],
        "slug": row["slug"],
        "label": row["label"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "revoked": bool(row["revoked"]),
        "last_accessed": row["last_accessed"],
        "ip_allowlist": ip_list,
        "country_allowlist": country_list,
        "entity_count": count,
        "entity_ids": entity_ids,
        "starts_at": row["starts_at"] if "starts_at" in row.keys() else None,
        "recurrence": recurrence,
        "bound_claimed_at": row["bound_claimed_at"] if "bound_claimed_at" in row.keys() else None,
        "max_uses": row["max_uses"] if "max_uses" in row.keys() else None,
        "use_count": row["use_count"] if "use_count" in row.keys() else 0,
    }


def _activity_row_to_response(row: Any) -> dict:
    return {
        "timestamp": row["timestamp"],
        "activity": row["event_type"],
        "token_label": row["token_label"],
        "target_entity_id": row["entity_id"],
        "service": row["service"],
        "ip_address": row["ip_address"],
    }


@router.get("/tokens")
async def list_tokens(_: str = Depends(require_admin)) -> list[dict]:
    rows = await db.list_tokens()
    return [_row_to_response(r) for r in rows]


@router.get("/activity")
async def list_activity(
    limit: int = Query(default=50, ge=1, le=200),
    _: str = Depends(require_admin),
) -> list[dict]:
    rows = await db.list_access_logs(limit=limit)
    return [_activity_row_to_response(r) for r in rows]


@router.post("/tokens", status_code=status.HTTP_201_CREATED)
async def create_token(
    body: TokenCreateRequest,
    request: Request,
    _: str = Depends(require_admin),
) -> dict:
    # Validate IP CIDR list if provided directly
    if body.ip_allowlist:
        for cidr in body.ip_allowlist:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"Invalid CIDR: {cidr}",
                )

    # Country allowlist: resolve to the actual CIDRs enforced by guest.py.
    # country_allowlist itself is stored too, purely so the dashboard can
    # show "Spain, Portugal" instead of the few thousand resolved CIDRs.
    resolved_ip_allowlist = body.ip_allowlist
    if body.country_allowlist:
        try:
            resolved_ip_allowlist = await geoip.resolve_countries_to_cidrs(body.country_allowlist)
        except geoip.CountryResolutionError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            )

    slug = body.slug or secrets.token_hex(16)
    if body.expires_in_seconds == NEVER_EXPIRES_SECONDS:
        expires_at = NEVER_EXPIRES_SECONDS
    else:
        expires_at = int(time.time()) + body.expires_in_seconds

    if body.starts_at is not None and body.starts_at >= expires_at:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="starts_at must be before expires_at",
        )

    # Ensure slug uniqueness
    existing = await db.get_token_by_slug(slug)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Slug '{slug}' already exists",
        )

    row = await db.create_token(
        label=body.label,
        slug=slug,
        entity_ids=body.entity_ids,
        expires_at=expires_at,
        ip_allowlist=resolved_ip_allowlist,
        country_allowlist=body.country_allowlist,
        starts_at=body.starts_at,
        recurrence=body.recurrence.model_dump() if body.recurrence else None,
        max_uses=body.max_uses,
    )
    entity_ids = await db.get_token_entities(row["id"])
    return _row_to_response(row, entity_ids)


@router.patch("/tokens/{token_id}/schedule")
async def update_token_schedule(
    token_id: str,
    body: TokenUpdateScheduleRequest,
    _: str = Depends(require_admin),
) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if body.starts_at is not None and row["expires_at"] != NEVER_EXPIRES_SECONDS and body.starts_at >= row["expires_at"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="starts_at must be before expires_at",
        )
    await db.update_token_schedule(
        token_id,
        starts_at=body.starts_at,
        recurrence=body.recurrence.model_dump() if body.recurrence else None,
    )
    row = await db.get_token_by_id(token_id)
    return _row_to_response(row)


@router.patch("/tokens/{token_id}/unbind")
async def unbind_token(token_id: str, _: str = Depends(require_admin)) -> dict:
    """Release the single-browser binding so the guest link can be claimed
    again — e.g. the guest lost/changed phone or cleared cookies."""
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    await db.unbind_token(token_id)
    row = await db.get_token_by_id(token_id)
    return _row_to_response(row)


@router.get("/tokens/{token_id}")
async def get_token(token_id: str, _: str = Depends(require_admin)) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    entity_ids = await db.get_token_entities(token_id)
    return _row_to_response(row, entity_ids)


@router.patch("/tokens/{token_id}/entities")
async def update_token_entities(
    token_id: str,
    body: TokenUpdateEntitiesRequest,
    _: str = Depends(require_admin),
) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if row["revoked"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot edit entities on a revoked token",
        )
    await db.update_token_entities(token_id, body.entity_ids)
    await ha_client.invalidate_entity_cache(token_id)
    entity_ids = await db.get_token_entities(token_id)
    row = await db.get_token_by_id(token_id)
    return _row_to_response(row, entity_ids)


@router.patch("/tokens/{token_id}/expiry")
async def update_token_expiry(
    token_id: str,
    body: TokenUpdateExpiryRequest,
    _: str = Depends(require_admin),
) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if body.expires_in_seconds == NEVER_EXPIRES_SECONDS:
        new_expires = NEVER_EXPIRES_SECONDS
    else:
        new_expires = int(time.time()) + body.expires_in_seconds
    await db.update_token_expiry(token_id, new_expires)
    # Un-revoke if the token was revoked (admin is explicitly renewing it)
    if row["revoked"]:
        await db.unrevoke_token(token_id)
    row = await db.get_token_by_id(token_id)
    return _row_to_response(row)


@router.post("/tokens/{token_id}/revoke")
async def revoke_token(token_id: str, _: str = Depends(require_admin)) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    await db.revoke_token(token_id)
    # Notify connected SSE clients
    if not row["revoked"]:
        await ha_client.broadcast_token_expired(token_id)
    return {"ok": True}


@router.delete("/tokens/{token_id}")
async def delete_token(token_id: str, _: str = Depends(require_admin)) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    await ha_client.broadcast_token_expired(token_id)
    await db.delete_token(token_id)
    return {"ok": True}


# ---------------------------------------------------------------------------
# HA entity list proxy
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Presence proofs (see app/presence.py)
# ---------------------------------------------------------------------------

@router.get("/presence")
async def presence_status(_: str = Depends(require_admin)) -> dict:
    """What presence configuration is live, and is Bluetooth actually working.

    Read-only: these come from the add-on options / environment, like every
    other deployment setting, so the panel reports them rather than editing
    them. What the panel *does* add is the calibration below, because the door
    scanner's MAC cannot reasonably be guessed by hand.
    """
    ble_enabled = "ha_ble" in settings.presence_modes
    names = await _device_names()
    return {
        "modes": settings.presence_modes,
        "policy": settings.presence_policy,
        "bluetooth": {
            "enabled": ble_enabled,
            # Distinguishes "you turned it on but HA won't stream to us" from
            # "you turned it on but never picked a door scanner".
            "streaming": ha_client.is_ble_healthy() if ble_enabled else False,
            "scanners": [_named_scanner(mac, names) for mac in settings.ble_scanners],
            "min_rssi": settings.ble_min_rssi,
            "max_age_seconds": settings.ble_max_age_seconds,
        },
    }


async def _device_names() -> dict[str, str]:
    """Never fatal: a nameless scanner is a cosmetic loss, not a broken panel."""
    try:
        return await ha_client.get_device_mac_names()
    except Exception:
        logger.warning("Could not read the HA device registry for scanner names")
        return {}


def _named_scanner(mac: str, names: dict[str, str]) -> dict:
    name, approximate = presence.match_scanner_name(mac, names)
    return {"source": mac, "name": name, "approximate": approximate}


async def _name_calibration(snapshot: dict) -> dict:
    names = await _device_names()
    for device in snapshot["devices"]:
        for scanner in device["scanners"]:
            scanner.update(_named_scanner(scanner["source"], names))
    return snapshot


@router.post("/presence/calibration")
async def presence_calibration_start(_: str = Depends(require_admin)) -> dict:
    if "ha_ble" not in settings.presence_modes:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Enable the ha_ble presence mode first",
        )
    await presence.start_calibration()
    return await _name_calibration(await presence.calibration_snapshot())


@router.delete("/presence/calibration")
async def presence_calibration_stop(_: str = Depends(require_admin)) -> dict:
    await presence.stop_calibration()
    return await _name_calibration(await presence.calibration_snapshot())


@router.get("/presence/calibration")
async def presence_calibration(_: str = Depends(require_admin)) -> dict:
    return await _name_calibration(await presence.calibration_snapshot())


@router.get("/ha/entities")
async def ha_entities(_: str = Depends(require_admin)) -> list[dict]:
    try:
        states = await ha_client.get_states()
    except Exception:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Home Assistant unreachable")
    # Only return entities whose domain guests can either control or view.
    return [
        {
            "entity_id": s["entity_id"],
            "friendly_name": s.get("attributes", {}).get("friendly_name", s["entity_id"]),
            "domain": domain,
            "state": s["state"],
        }
        for s in states
        if (domain := s["entity_id"].split(".")[0]) in SUPPORTED_DOMAINS
    ]


def _words(entity_id: str, friendly_name: str) -> set[str]:
    """Whole words of an entity's id and friendly name, lowercased. Splitting on
    underscores too is what makes `input_button.portal_qvadis` match "portal"
    while `button.cafetera_cancelar` no longer matches "cancela"."""
    return set(re.split(r"[\W_]+", f"{entity_id} {friendly_name}".lower()))


def _matches_category(entity_id: str, friendly_name: str, domain: str, category: str) -> bool:
    words = _words(entity_id, friendly_name)
    if category == "access":
        if words & EXCLUDE_ACCESS_KEYWORDS:
            return False
        return domain in ACCESS_DOMAINS and bool(words & ACCESS_KEYWORDS)
    if category == "lights":
        if words & EXCLUDE_LIGHT_KEYWORDS:
            return False
        if domain in LIGHT_DOMAINS:
            return True
        return domain == "switch" and bool(words & LIGHT_KEYWORDS)
    return False


@router.get("/ha/suggested-entities")
async def suggested_entities(
    categories: str = Query(default="access,lights"),
    _: str = Depends(require_admin),
) -> list[dict]:
    """Narrow, keyword/domain-based entity suggestions for the invitation-mode
    picker (Access only / Lights only / Access and lights) — intentionally
    much narrower than a "detect every integration" dashboard: only what's
    plausibly useful to hand to a guest link, pre-selected (not auto-added),
    the admin can still edit freely afterwards."""
    wanted = {c.strip() for c in categories.split(",") if c.strip()}
    try:
        states = await ha_client.get_states()
    except Exception:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Home Assistant unreachable")

    results = []
    for s in states:
        entity_id = s["entity_id"]
        domain = entity_id.split(".")[0]
        friendly_name = s.get("attributes", {}).get("friendly_name", entity_id)
        for category in ("access", "lights"):
            if category in wanted and _matches_category(entity_id, friendly_name, domain, category):
                results.append({
                    "entity_id": entity_id,
                    "friendly_name": friendly_name,
                    "domain": domain,
                    "category": category,
                })
    return results
