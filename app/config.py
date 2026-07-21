from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
