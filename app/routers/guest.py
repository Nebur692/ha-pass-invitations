"""Guest API router: PWA shell, state, SSE, and command proxy."""
# Security note: The slug in the URL acts as a bearer token — knowing the
# slug grants access. CSRF is mitigated by the fact that all state-changing
# operations require the slug in the URL path (not a cookie). The admin
# dashboard uses SameSite=strict cookies for CSRF protection.
#
# Device-binding note: a second, separate cookie (hp_bind_<slug>, see
# _verify_or_claim_binding) is set on first use to lock a guest link to the
# browser that first opened it. This does NOT replace slug-based auth above —
# it's an additional restriction, never a substitute for the slug — and it's
# SameSite=Strict/HttpOnly so it plays no role in CSRF.
import asyncio
import ipaddress
import json
import logging
import re
import secrets
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import AsyncIterator
from zoneinfo import ZoneInfo

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException, Path, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app import database as db
from app import ha_client
from app import presence
from app.config import settings
from app.context import base_context
from app import i18n
from app.models import (
    ALLOWED_SERVICES,
    CommandRequest,
    FORBIDDEN_DATA_KEYS,
    LOCAL_ONLY_DOMAINS,
    NEVER_EXPIRES_SECONDS,
)
from app.rate_limiter import rate_limiter

router = APIRouter(prefix="/g")
logger = logging.getLogger(__name__)

# L-31: Named constant for SSE keepalive interval
SSE_KEEPALIVE_SECONDS = 25

# Global rate limit for guest command proxy (requests per minute per token).
# Hardcoded — no comparable self-hosted app exposes per-user rate limits.
COMMAND_RPM = 30

# L-8: Whitelist of allowed SSE event types
_ALLOWED_SSE_EVENTS = {"state_change", "token_expired", "reconnected"}

# M-27: Simple TTL cache for HA state list
_states_cache: list[dict] | None = None
_states_cache_ts: float = 0
STATE_CACHE_TTL = 30  # seconds
ACTIVITY_EVENT_TYPE = "ha_pass_activity"
ACTIVITY_SCHEMA_VERSION = 1

# Where the welcome page points guests who want the Android app. Not a setting:
# the app is generic and one build serves every installation, so there is only
# ever one place to get it.
ANDROID_RELEASE_URL = "https://github.com/Nebur692/ha-pass-invitations-android/releases/latest"
PAGE_LOAD_EVENT_DEBOUNCE_SECONDS = 30
_page_load_activity_ts: dict[str, float] = {}


async def _get_cached_states() -> list[dict]:
    global _states_cache, _states_cache_ts
    now = time.monotonic()
    if _states_cache is not None and (now - _states_cache_ts) < STATE_CACHE_TTL:
        return _states_cache
    _states_cache = await ha_client.get_states()
    _states_cache_ts = now
    return _states_cache


templates = Jinja2Templates(directory="templates")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _guest_i18n_ctx(request: Request) -> dict:
    lang = i18n.get_guest_lang(request)
    return {
        "lang": lang,
        "t": i18n.make_t(i18n.GUEST_STRINGS, lang),
        "strings_json": json.dumps(i18n.GUEST_STRINGS.get(lang, i18n.GUEST_STRINGS[i18n.DEFAULT_LANG])),
    }

def _client_ip(request: Request) -> str:
    """Extract the client IP from X-Forwarded-For (set by reverse proxy).

    IMPORTANT: HAPass MUST be deployed behind a reverse proxy (Caddy, nginx,
    Cloudflare Tunnel, etc.) that overwrites the X-Forwarded-For header with the
    true client IP. Without this, clients can spoof their IP to bypass allowlists.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _ip_in_cidrs(client_ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(cidr, strict=False) for cidr in cidrs)


def _enforce_ip_allowlist(row, request: Request) -> None:
    if not row["ip_allowlist"]:
        return
    client_ip = _client_ip(request)
    allowed_cidrs: list[str] = json.loads(row["ip_allowlist"])
    if client_ip == "unknown" or not _ip_in_cidrs(client_ip, allowed_cidrs):
        detail = "Invalid client IP" if client_ip == "unknown" else "IP not allowed"
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


async def _enforce_presence_for_domain(
    entity_domain: str, request: Request, token_id: str
) -> None:
    """Fixed security policy (not per-token): commands on LOCAL_ONLY_DOMAINS
    (locks, buttons, covers — anything that opens something physical) require
    a server-verified proof that the guest is actually here. Lights and other
    domains are never restricted this way. Viewing the guest link itself
    (page/state/stream) is also never restricted this way — only command
    execution on these specific domains.

    Which proofs count is configurable; see app/presence.py."""
    if entity_domain not in LOCAL_ONLY_DOMAINS:
        return
    try:
        await presence.check(token_id, _client_ip(request))
    except presence.PresenceDenied as denied:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=denied.detail
        ) from denied


# ---------------------------------------------------------------------------
# Scheduling (advance start + recurring weekly windows)
# ---------------------------------------------------------------------------

class TokenState(str, Enum):
    ACTIVE = "active"
    GONE = "gone"                     # not found / revoked / past expires_at
    NOT_YET_ACTIVE = "not_yet_active"  # before starts_at, or outside today's recurrence window
    USED_UP = "used_up"               # max_uses reached — distinct from GONE for guest messaging


def _within_recurrence(recurrence: dict, now: int) -> bool:
    local = datetime.fromtimestamp(now, tz=ZoneInfo(settings.timezone))
    if local.weekday() not in recurrence["weekdays"]:
        return False
    hhmm = local.strftime("%H:%M")
    return recurrence["start"] <= hhmm < recurrence["end"]


def _token_state(row, now: int) -> TokenState:
    if row["revoked"] or row["expires_at"] <= now:
        return TokenState.GONE
    if row["max_uses"] is not None and row["use_count"] >= row["max_uses"]:
        return TokenState.USED_UP
    if row["starts_at"] is not None and row["starts_at"] > now:
        return TokenState.NOT_YET_ACTIVE
    if row["recurrence"]:
        if not _within_recurrence(json.loads(row["recurrence"]), now):
            return TokenState.NOT_YET_ACTIVE
    return TokenState.ACTIVE


def _gone_reason(row) -> str:
    """Distinguishes why a token is gone, for guest-facing messaging."""
    if row is not None and row["revoked"]:
        return "revoked"
    return "expired"


def _next_available_at(row, now: int) -> int | None:
    """Best-effort estimate of when a NOT_YET_ACTIVE token becomes usable
    again, for display to the guest. Returns None if there's nothing to wait
    for (shouldn't normally be called in that case)."""
    if row["starts_at"] is not None and row["starts_at"] > now:
        starts_at = row["starts_at"]
    else:
        starts_at = now

    if not row["recurrence"]:
        return starts_at

    recurrence = json.loads(row["recurrence"])
    tz = ZoneInfo(settings.timezone)
    cursor = datetime.fromtimestamp(starts_at, tz=tz)
    # Scan forward day by day (max 8 to cover a full week + today) for the
    # next day matching the recurrence, then anchor to its start time.
    for _ in range(8):
        if cursor.weekday() in recurrence["weekdays"]:
            hh, mm = (int(x) for x in recurrence["start"].split(":"))
            candidate = cursor.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if candidate.timestamp() >= starts_at:
                return int(candidate.timestamp())
        cursor = (cursor + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return None


# ---------------------------------------------------------------------------
# Single-browser binding
# ---------------------------------------------------------------------------

def _binding_cookie_name(slug: str) -> str:
    return f"hp_bind_{slug}"


# The Android app has no cookie jar, and storing the secret in the OS keystore
# is stronger than a cookie anyway — so it presents the same secret in a header.
BINDING_HEADER = "X-HAPass-Binding"


def _incoming_binding(request: Request, slug: str) -> str | None:
    return request.headers.get(BINDING_HEADER) or request.cookies.get(
        _binding_cookie_name(slug)
    )


async def _verify_or_claim_binding(row, request: Request, claim: bool = True) -> str | None:
    """Enforces that a guest link can only ever be used from the device
    that first opened it. Returns a secret the caller must hand back (as a
    cookie for browsers, in the response body at enrollment for the app) if
    this request just claimed the token; returns None if verification passed
    against an already-bound token (nothing new to set). Raises 403 if bound
    to a different device.

    With `claim=False` an unbound token is left alone and None is returned.
    Merely *fetching* a URL must never consume the one binding a link has:
    chat apps fetch it themselves to build a preview card, and in production
    WhatsApp's fetcher claimed three links within seconds of them being sent,
    leaving the actual guest locked out. Claiming is therefore a deliberate
    act — see the /bind endpoint behind the welcome page's button.
    """
    slug = row["slug"]
    incoming = _incoming_binding(request, slug)

    if row["bound_secret"] is None:
        if not claim:
            return None
        secret = secrets.token_hex(32)
        await db.claim_token_binding(row["id"], secret, int(time.time()))
        fresh = await db.get_token_by_slug(slug)
        if fresh["bound_secret"] == secret:
            return secret  # we won the claim race — caller sets the cookie
        row = fresh  # lost the race to a concurrent request — verify below

    if not incoming or not secrets.compare_digest(incoming, row["bound_secret"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This link is already in use on another device",
        )
    return None


def _is_https(request: Request) -> bool:
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    return request.url.scheme == "https" or forwarded_proto == "https"


def _set_binding_cookie(response: Response, request: Request, slug: str, secret: str, expires_at: int) -> None:
    max_age = max(1, expires_at - int(time.time())) if expires_at < NEVER_EXPIRES_SECONDS else None
    response.set_cookie(
        _binding_cookie_name(slug),
        secret,
        httponly=True,
        samesite="strict",
        secure=_is_https(request),
        path=f"/g/{slug}",
        max_age=max_age,
    )


async def _validate_token(slug: str, request: Request):
    """Load and validate a token by slug. Raises HTTP 410 if gone (not found,
    revoked, past expiry — unchanged from before), or 403 if scheduled but
    not currently active (before starts_at, or outside a recurrence window)."""
    row = await db.get_token_by_slug(slug)
    if not row:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Access unavailable")

    now = int(time.time())
    state = _token_state(row, now)
    if state is TokenState.GONE:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Access unavailable")
    if state is TokenState.USED_UP:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Access already used")
    if state is TokenState.NOT_YET_ACTIVE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access not yet active")

    _enforce_ip_allowlist(row, request)

    return row


async def _fire_activity_event(payload: dict) -> None:
    try:
        await ha_client.fire_event(ACTIVITY_EVENT_TYPE, payload)
    except Exception as exc:
        logger.warning("Failed to emit HA activity event: %s", exc)
    try:
        await ha_client.logbook_log(_logbook_payload(payload))
    except Exception as exc:
        logger.warning("Failed to write HA logbook activity: %s", exc)


def _logbook_payload(payload: dict) -> dict:
    token_label = payload["token_label"]
    if payload["activity"] == "command":
        target_entity_id = payload["target_entity_id"]
        data = {
            "name": "HAPass",
            "message": f"{token_label} used {payload['service']} on {target_entity_id}",
            "entity_id": target_entity_id,
        }
        if target_entity_id and "." in target_entity_id:
            data["domain"] = target_entity_id.split(".", 1)[0]
        return data
    if payload["activity"] == "first_use":
        # "Check-in" moment: this is when the link got bound to a
        # device for the first time — distinct from every subsequent page_load
        # so a host-facing automation can notify on this specific event.
        return {
            "name": "HAPass",
            "message": f"{token_label} opened the link for the first time",
        }
    return {
        "name": "HAPass",
        "message": f"{token_label} opened guest link",
    }


def _activity_payload(
    row,
    activity: str,
    target_entity_id: str | None = None,
    service: str | None = None,
) -> dict:
    return {
        "schema_version": ACTIVITY_SCHEMA_VERSION,
        "activity": activity,
        "token_label": row["label"],
        "target_entity_id": target_entity_id,
        "service": service,
    }


def _schedule_activity_event(background_tasks: BackgroundTasks, payload: dict) -> None:
    background_tasks.add_task(_fire_activity_event, payload)


def _schedule_page_load_activity(background_tasks: BackgroundTasks, row) -> None:
    now = time.monotonic()
    cutoff = now - PAGE_LOAD_EVENT_DEBOUNCE_SECONDS
    for token_id, last_emitted in list(_page_load_activity_ts.items()):
        if last_emitted < cutoff:
            del _page_load_activity_ts[token_id]
    token_id = row["id"]
    last_emitted = _page_load_activity_ts.get(token_id)
    if last_emitted is not None and (now - last_emitted) < PAGE_LOAD_EVENT_DEBOUNCE_SECONDS:
        return
    _page_load_activity_ts[token_id] = now
    _schedule_activity_event(background_tasks, _activity_payload(row, "page_load"))


# ---------------------------------------------------------------------------
# PWA shell
# ---------------------------------------------------------------------------

@router.get("/{slug}", response_class=HTMLResponse)
async def guest_pwa(background_tasks: BackgroundTasks, request: Request, slug: str = Path(max_length=64)):
    row = await db.get_token_by_slug(slug)
    now = int(time.time())
    state = _token_state(row, now) if row else TokenState.GONE

    if state is TokenState.GONE:
        ctx = base_context(request)
        ctx.update(_guest_i18n_ctx(request))
        ctx.update({"slug": slug, "contact_message": settings.contact_message, "reason": _gone_reason(row)})
        return templates.TemplateResponse(request, "expired.html", ctx, status_code=410)

    if state is TokenState.USED_UP:
        ctx = base_context(request)
        ctx.update(_guest_i18n_ctx(request))
        ctx.update({"slug": slug, "contact_message": settings.contact_message, "reason": "used_up"})
        return templates.TemplateResponse(request, "expired.html", ctx, status_code=410)

    # Never claims: this same request is what a chat app makes to build a link
    # preview. A device that isn't the bound one still gets turned away here,
    # it just no longer *becomes* the bound one by asking.
    try:
        _enforce_ip_allowlist(row, request)
        await _verify_or_claim_binding(row, request, claim=False)
    except HTTPException as exc:
        ctx = base_context(request)
        ctx.update(_guest_i18n_ctx(request))
        ctx.update({
            "slug": slug,
            "contact_message": settings.contact_message,
            # Saying "expired" here sent the admin hunting through dates for a
            # problem that was never about time.
            "reason": "another_device" if exc.status_code == status.HTTP_403_FORBIDDEN else "expired",
        })
        return templates.TemplateResponse(request, "expired.html", ctx, status_code=exc.status_code)

    if state is TokenState.NOT_YET_ACTIVE:
        ctx = base_context(request)
        ctx.update(_guest_i18n_ctx(request))
        ctx.update({
            "slug": slug,
            "label": row["label"],
            "available_at": _next_available_at(row, now),
            "contact_message": settings.contact_message,
        })
        return templates.TemplateResponse(request, "not_active_yet.html", ctx, status_code=403)

    # Unclaimed link: hand out the welcome page instead of the controls. It
    # says nothing about the home, so a preview card leaks nothing either.
    if row["bound_secret"] is None:
        ctx = base_context(request)
        ctx.update(_guest_i18n_ctx(request))
        ctx.update({
            "slug": slug,
            "contact_message": settings.contact_message,
            "android_release_url": ANDROID_RELEASE_URL,
        })
        return templates.TemplateResponse(request, "welcome.html", ctx)

    await db.touch_token(row["id"])
    await db.log_access(
        token_id=row["id"],
        event_type="page_load",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    _schedule_page_load_activity(background_tasks, row)
    ctx = base_context(request)
    ctx.update(_guest_i18n_ctx(request))
    ctx.update({
        "slug": slug,
        "label": row["label"],
        "expires_at": row["expires_at"],
        "contact_message": settings.contact_message,
        "never_expires": NEVER_EXPIRES_SECONDS,
    })
    return templates.TemplateResponse(request, "guest_pwa.html", ctx)


# ---------------------------------------------------------------------------
# Claiming the link for this device
# ---------------------------------------------------------------------------

@router.post("/{slug}/bind")
async def guest_bind(
    background_tasks: BackgroundTasks,
    request: Request,
    response: Response,
    slug: str = Path(max_length=64),
):
    """Claim this guest link for the device that asked.

    Split out of the page load on purpose. A POST needs a deliberate tap, and
    link-preview fetchers only ever issue GETs, so the link survives being
    shared through a chat app.
    """
    row = await _validate_token(slug, request)
    new_binding_secret = await _verify_or_claim_binding(row, request)
    if new_binding_secret:
        _set_binding_cookie(response, request, slug, new_binding_secret, row["expires_at"])
        _schedule_activity_event(background_tasks, _activity_payload(row, "first_use"))
    return {"ok": True}


# ---------------------------------------------------------------------------
# Dynamic PWA manifest
# ---------------------------------------------------------------------------

@router.get("/{slug}/manifest.json")
async def guest_manifest(request: Request, slug: str = Path(max_length=64)):
    bp = request.state.ingress_path
    manifest = {  # colors must match static/input.css
        "name": settings.app_name,
        "short_name": settings.app_name[:12],
        "description": "Temporary home controls",
        "start_url": f"{bp}/g/{slug}",
        "scope": f"{bp}/g/{slug}",
        "display": "standalone",
        "background_color": settings.brand_bg,
        "theme_color": settings.brand_primary,
        "orientation": "portrait",
        "icons": [
            {"src": f"{bp}/static/icons/icon-192.png", "sizes": "192x192",
             "type": "image/png", "purpose": "any"},
            {"src": f"{bp}/static/icons/icon-512.png", "sizes": "512x512",
             "type": "image/png", "purpose": "any"},
            {"src": f"{bp}/static/icons/icon-maskable-192.png", "sizes": "192x192",
             "type": "image/png", "purpose": "maskable"},
            {"src": f"{bp}/static/icons/icon-maskable-512.png", "sizes": "512x512",
             "type": "image/png", "purpose": "maskable"},
        ],
    }
    return JSONResponse(manifest)


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------

@router.get("/{slug}/state")
async def guest_state(request: Request, response: Response, slug: str = Path(max_length=64)):
    row = await _validate_token(slug, request)
    new_binding_secret = await _verify_or_claim_binding(row, request)
    if new_binding_secret:
        _set_binding_cookie(response, request, slug, new_binding_secret, row["expires_at"])
    entity_ids = await db.get_token_entities(row["id"])

    allowed = set(entity_ids)
    all_states = await _get_cached_states()
    states = {}
    for s in all_states:
        eid = s.get("entity_id", "")
        if eid in allowed:
            states[eid] = s
    for eid in entity_ids:
        if eid not in states:
            states[eid] = {"entity_id": eid, "state": "unavailable", "attributes": {}}

    return {"entities": entity_ids, "states": states}


# ---------------------------------------------------------------------------
# Native app enrollment
# ---------------------------------------------------------------------------

@router.post("/{slug}/enroll")
async def guest_enroll(request: Request, slug: str = Path(max_length=64)):
    """Hand a native app everything it needs to act as this guest's device.

    Claims the same single-device binding a browser would, but returns the
    secret in the body instead of a cookie. A link already opened in a browser
    is therefore already bound and will be refused here — recovering from that
    is what the admin panel's "Unbind" button is for.
    """
    row = await _validate_token(slug, request)
    new_binding_secret = await _verify_or_claim_binding(row, request)

    ble_enabled = "ha_ble" in settings.presence_modes
    body = {
        "slug": slug,
        "app_name": settings.app_name,
        "language": i18n.detect_lang(
            request.headers.get("accept-language", ""), i18n.GUEST_SUPPORTED_LANGS
        ),
        "presence": {
            "bluetooth": ble_enabled,
            # The app rebuilds the advertised UUID as prefix + HMAC(secret,
            # window); see app/presence.py for the derivation it must mirror.
            "uuid_prefix": presence.UUID_PREFIX if ble_enabled else None,
            "window_seconds": presence.CODE_WINDOW_SECONDS,
        },
    }
    # Only present the first time: afterwards the app already holds it, and
    # re-sending it on every call would put it back in reach of a copied link.
    if new_binding_secret:
        body["binding_secret"] = new_binding_secret
    return body


# ---------------------------------------------------------------------------
# SSE stream
# ---------------------------------------------------------------------------

async def _event_generator(token_id: str, slug: str, request: Request) -> AsyncIterator[str]:
    q = await ha_client.subscribe(token_id)
    try:
        # M-5: Expose WS health in SSE connected event
        yield f"event: connected\ndata: {{\"ws_healthy\": {str(ha_client.is_ws_healthy()).lower()}}}\n\n"

        while True:
            if await request.is_disconnected():
                break

            try:
                event = await asyncio.wait_for(q.get(), timeout=SSE_KEEPALIVE_SECONDS)
                # L-8: Only forward whitelisted event types
                if event["type"] not in _ALLOWED_SSE_EVENTS:
                    continue
                yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                if event["type"] == "token_expired":
                    break
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"

    finally:
        await ha_client.unsubscribe(token_id, q)


@router.get("/{slug}/stream")
async def guest_stream(request: Request, slug: str = Path(max_length=64)):
    row = await _validate_token(slug, request)
    new_binding_secret = await _verify_or_claim_binding(row, request)
    resp = StreamingResponse(
        _event_generator(row["id"], slug, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
    if new_binding_secret:
        _set_binding_cookie(resp, request, slug, new_binding_secret, row["expires_at"])
    return resp


# ---------------------------------------------------------------------------
# Command proxy
# ---------------------------------------------------------------------------

@router.post("/{slug}/command")
async def guest_command(
    body: CommandRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    response: Response,
    slug: str = Path(max_length=64),
):
    row = await _validate_token(slug, request)
    token_id = row["id"]

    new_binding_secret = await _verify_or_claim_binding(row, request)
    if new_binding_secret:
        _set_binding_cookie(response, request, slug, new_binding_secret, row["expires_at"])

    allowed = await rate_limiter.check(token_id, COMMAND_RPM)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

    # L-6: Validate service format before processing
    if not re.match(r'^[a-z_]+\.[a-z_]+$', body.service) and not re.match(r'^[a-z_]+$', body.service):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid service format",
        )

    entity_ids = await db.get_token_entities(token_id)
    if body.entity_id not in entity_ids:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Entity not in allowlist")

    entity_domain = body.entity_id.split(".")[0]
    await _enforce_presence_for_domain(entity_domain, request, token_id)

    if "." in body.service:
        svc_domain, svc_name = body.service.split(".", 1)
        if svc_domain != entity_domain:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Service domain does not match entity",
            )
    else:
        svc_name = body.service

    allowed_svc = ALLOWED_SERVICES.get(entity_domain)
    if not allowed_svc or svc_name not in allowed_svc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Service '{svc_name}' not allowed for {entity_domain}",
        )

    clean_data = {k: v for k, v in body.data.items() if k not in FORBIDDEN_DATA_KEYS}
    service_data = {**clean_data, "entity_id": body.entity_id}

    try:
        result = await ha_client.call_service(entity_domain, svc_name, service_data)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Service call failed")
    except Exception:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Service call failed")

    if row["max_uses"] is not None:
        await db.increment_token_use_count(token_id)

    await db.log_access(
        token_id=token_id,
        event_type="command",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        entity_id=body.entity_id,
        service=body.service,
    )
    _schedule_activity_event(
        background_tasks,
        _activity_payload(
            row,
            "command",
            target_entity_id=body.entity_id,
            service=f"{entity_domain}.{svc_name}",
        ),
    )

    return {"ok": True}
