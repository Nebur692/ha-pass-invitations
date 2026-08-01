from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Lives here rather than in app/presence.py, which is where it belongs
# conceptually: presence.py imports `settings`, so a validator importing
# presence.py would close a cycle while this module is still executing.
# See app/presence.py for what each mode actually means.
VALID_PRESENCE_MODES = {"local_network", "ha_ble"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    admin_username: str = ""
    admin_password: str = ""
    ha_base_url: str = Field(min_length=1, pattern=r"^https?://")
    ha_token: str = Field(min_length=1)
    db_path: str = Field(default="/data/db.sqlite", min_length=1)
    app_name: str = "Home Access"
    contact_message: str = "Please request a new link from the person who shared this one."
    access_log_retention_days: int = Field(default=90, ge=1)
    brand_bg: str = "#F2F0E9"
    brand_primary: str = "#D9523C"
    supervisor_token: str = ""
    guest_url: str = ""
    # Used to evaluate recurring weekly schedules (see app/models.py
    # RecurrenceSchedule) in local time. A single household-wide zone —
    # this is one front door, not a multi-tenant service.
    timezone: str = "UTC"
    # CIDRs considered "on the home network". When non-empty, commands on
    # LOCAL_ONLY_DOMAINS (see app/models.py) are rejected unless the guest's
    # request originates from one of these ranges. Empty = no restriction
    # (today's behavior, fully backward compatible).
    local_network_cidrs: list[str] = Field(default_factory=list)

    # --- Presence proofs -------------------------------------------------
    # Which proofs of "the guest is physically here" are accepted before a
    # command on LOCAL_ONLY_DOMAINS runs. Default keeps today's behaviour
    # exactly. See app/presence.py for what each mode means.
    presence_modes: list[str] = Field(default_factory=lambda: ["local_network"])
    # "any": one satisfied proof is enough (recommended — lets PWA guests keep
    # using the home network while app guests use Bluetooth). "all": every
    # configured mode must pass.
    presence_policy: str = "any"
    # MAC addresses of the Home Assistant Bluetooth scanners that count as
    # "at the door". Deliberately fails closed: with ha_ble enabled and this
    # left empty, any scanner in the house would do, which is not proof of
    # being at the door — so the mode stays inactive instead.
    ble_scanners: list[str] = Field(default_factory=list)
    ble_min_rssi: int = -70
    ble_max_age_seconds: int = Field(default=30, ge=5)

    # --- Android app association ----------------------------------------
    # Served at /.well-known/assetlinks.json so an https guest link opens the
    # app directly. Every installation serves the same values, which is what
    # makes one published app work against all of them; overridable so anyone
    # who forks the app and signs it with their own key can self-host that too.
    # Empty fingerprints means "no app published yet" and the route 404s
    # rather than publishing an association Android would cache as broken.
    android_package: str = "io.github.nebur692.hapass"
    android_cert_fingerprints: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_presence(self):
        unknown = set(self.presence_modes) - VALID_PRESENCE_MODES
        if unknown:
            raise ValueError(
                f"Unknown presence_modes: {sorted(unknown)}. "
                f"Valid: {sorted(VALID_PRESENCE_MODES)}"
            )
        if self.presence_policy not in ("any", "all"):
            raise ValueError("presence_policy must be 'any' or 'all'")
        return self

    @model_validator(mode="after")
    def _require_credentials_in_standalone(self):
        if not self.supervisor_token:
            if len(self.admin_password) < 8:
                raise ValueError("admin_password must be at least 8 characters in standalone mode")
            if not self.admin_username:
                raise ValueError("admin_username is required in standalone mode")
        return self

    @model_validator(mode="after")
    def _validate_timezone(self):
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"Invalid timezone: {self.timezone!r}") from exc
        return self


settings = Settings()
