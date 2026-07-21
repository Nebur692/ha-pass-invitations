"""Pydantic request/response models."""
from typing import Any
from pydantic import BaseModel, Field, model_validator

NEVER_EXPIRES_SECONDS = 4102444800  # 2099-12-31T00:00:00Z

# Services guests are permitted to call, keyed by entity domain.
# Script/scene/automation domains are intentionally excluded —
# they execute arbitrary automations and bypass entity scoping.
ALLOWED_SERVICES: dict[str, set[str]] = {
    "light":         {"turn_on", "turn_off", "toggle"},
    "switch":        {"turn_on", "turn_off", "toggle"},
    "input_boolean": {"turn_on", "turn_off", "toggle"},
    "climate":       {"set_temperature", "set_hvac_mode", "turn_on", "turn_off"},
    "lock":          {"lock", "unlock", "open"},
    "media_player":  {"media_play", "media_pause", "media_stop", "volume_set",
                      "media_play_pause", "turn_on", "turn_off"},
    "cover":         {"open_cover", "close_cover", "stop_cover"},
    "fan":           {"turn_on", "turn_off", "toggle", "set_percentage"},
    # Single, stateless trigger — no parameters, nothing to read back besides
    # a timestamp. Lower risk than domains already above (e.g. climate).
    "button":        {"press"},
    "input_button":  {"press"},
}

READ_ONLY_DOMAINS: set[str] = {"sensor", "binary_sensor"}
SUPPORTED_DOMAINS: set[str] = set(ALLOWED_SERVICES) | READ_ONLY_DOMAINS

# Keys that could bypass the entity allowlist if forwarded to HA
FORBIDDEN_DATA_KEYS = {"entity_id", "device_id", "area_id", "floor_id", "label_id"}

# Domains guarded behind "must be on the home network" for command execution
# (see app/config.py Settings.local_network_cidrs and app/routers/guest.py).
# Fixed security policy, not configurable per-token: viewing the link/state
# and controlling e.g. lights remotely stays unrestricted; opening doors/gates
# does not.
LOCAL_ONLY_DOMAINS: set[str] = {"lock", "button", "input_button", "cover"}

# Suggested-entity categories for the admin "suggest entities" / invitation
# mode picker. Keyword matching is against entity_id and friendly_name,
# case-insensitive. Deliberately narrow (unlike a "detect every integration"
# dashboard) — only what's actually useful to hand to a guest.
ACCESS_KEYWORDS = {"portal", "puerta", "door", "gate", "garaje", "verja", "cancela", "cerradura", "entrance", "garage"}
LIGHT_KEYWORDS = {"luz", "lampara", "light"}
ACCESS_DOMAINS = {"lock", "input_button", "button", "cover"}
LIGHT_DOMAINS = {"light"}


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class RecurrenceSchedule(BaseModel):
    """A recurring weekly access window, e.g. every Tue/Thu 09:00-13:00.

    Evaluated in app.config.settings.timezone. Applies *within* the token's
    starts_at/expires_at outer bound, not instead of it.
    """
    weekdays: list[int] = Field(..., min_length=1)  # 0=Monday .. 6=Sunday, matches datetime.weekday()
    start: str = Field(..., pattern=r"^([01]\d|2[0-3]):[0-5]\d$")  # "HH:MM"
    end: str = Field(..., pattern=r"^([01]\d|2[0-3]):[0-5]\d$")

    @model_validator(mode="after")
    def _validate(self):
        for d in self.weekdays:
            if not (0 <= d <= 6):
                raise ValueError("weekdays must be 0-6 (0=Monday)")
        if self.end <= self.start:
            # Overnight-crossing windows (end < start) are not supported —
            # reject rather than silently misbehave.
            raise ValueError("end must be after start (overnight windows not supported)")
        return self


class TokenCreateRequest(BaseModel):
    label: str = Field(..., min_length=1, max_length=200)
    slug: str | None = Field(default=None, pattern=r"^[a-z0-9_-]{1,64}$")
    entity_ids: list[str] = Field(..., min_length=1)
    expires_in_seconds: int = Field(..., gt=0)
    ip_allowlist: list[str] | None = None
    # Advance/recurring scheduling — all optional, None preserves today's
    # "active immediately" behavior.
    starts_at: int | None = Field(default=None, gt=0)
    recurrence: RecurrenceSchedule | None = None
    # Automatic delivery of the guest link via an HA notify.* service.
    notify_service: str | None = Field(default=None, pattern=r"^notify\.[a-z0-9_]+$")
    notify_lead_seconds: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _validate_schedule(self):
        # starts_at vs. the resulting absolute expires_at needs "now", which
        # this model doesn't have (expires_in_seconds is relative) — that
        # comparison is done in the admin router instead.
        if self.notify_lead_seconds is not None and self.notify_service is None:
            raise ValueError("notify_lead_seconds requires notify_service")
        return self


class TokenUpdateEntitiesRequest(BaseModel):
    entity_ids: list[str] = Field(..., min_length=1)


class TokenUpdateExpiryRequest(BaseModel):
    expires_in_seconds: int = Field(..., gt=0)


class TokenUpdateScheduleRequest(BaseModel):
    starts_at: int | None = Field(default=None, gt=0)
    recurrence: RecurrenceSchedule | None = None


class CommandRequest(BaseModel):
    entity_id: str
    service: str  # e.g. "light.turn_on"
    data: dict[str, Any] = Field(default_factory=dict)


class TokenResponse(BaseModel):
    id: str
    slug: str
    label: str
    created_at: int
    expires_at: int
    revoked: bool
    last_accessed: int | None
    ip_allowlist: list[str] | None
    entity_count: int
    entity_ids: list[str] | None = None
    starts_at: int | None = None
    recurrence: dict | None = None
    notify_service: str | None = None
    notify_lead_seconds: int | None = None
    bound_claimed_at: int | None = None


class SuggestedEntity(BaseModel):
    entity_id: str
    friendly_name: str
    domain: str
    category: str  # "access" | "lights"
