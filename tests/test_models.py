"""Tests for Pydantic request/response models."""
import pytest
from pydantic import ValidationError

from app.models import (
    AdminLoginRequest,
    ALLOWED_SERVICES,
    CommandRequest,
    LOCAL_ONLY_DOMAINS,
    NEVER_EXPIRES_SECONDS,
    RecurrenceSchedule,
    SUPPORTED_DOMAINS,
    TokenCreateRequest,
    TokenUpdateEntitiesRequest,
    TokenUpdateExpiryRequest,
    TokenUpdateScheduleRequest,
)


class TestTokenCreateRequest:
    def test_valid_minimal(self):
        t = TokenCreateRequest(
            label="Guest",
            entity_ids=["light.living_room"],
            expires_in_seconds=3600,
        )
        assert t.label == "Guest"
        assert t.slug is None

    def test_valid_all_fields(self):
        t = TokenCreateRequest(
            label="Full",
            slug="my-slug",
            entity_ids=["light.a", "switch.b"],
            expires_in_seconds=7200,
            ip_allowlist=["192.168.1.0/24"],
        )
        assert t.slug == "my-slug"
        assert t.ip_allowlist == ["192.168.1.0/24"]

    def test_empty_label_rejected(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="",
                entity_ids=["light.a"],
                expires_in_seconds=3600,
            )

    def test_label_too_long(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="x" * 201,
                entity_ids=["light.a"],
                expires_in_seconds=3600,
            )

    def test_empty_entity_ids_rejected(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="Guest",
                entity_ids=[],
                expires_in_seconds=3600,
            )

    def test_invalid_slug_pattern(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="Guest",
                slug="UPPER_CASE",
                entity_ids=["light.a"],
                expires_in_seconds=3600,
            )

    def test_slug_with_spaces(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="Guest",
                slug="has spaces",
                entity_ids=["light.a"],
                expires_in_seconds=3600,
            )

    def test_zero_expires_rejected(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="Guest",
                entity_ids=["light.a"],
                expires_in_seconds=0,
            )

    def test_negative_expires_rejected(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="Guest",
                entity_ids=["light.a"],
                expires_in_seconds=-1,
            )

    def test_never_expires_value_accepted(self):
        """NEVER_EXPIRES_SECONDS is a valid expires_in_seconds value (gt=0)."""
        t = TokenCreateRequest(
            label="Forever",
            entity_ids=["light.a"],
            expires_in_seconds=NEVER_EXPIRES_SECONDS,
        )
        assert t.expires_in_seconds == NEVER_EXPIRES_SECONDS

    def test_valid_slug_patterns(self):
        """Slugs with lowercase, digits, hyphens, underscores are valid."""
        for slug in ["abc", "test-123", "my_token", "a-b_c"]:
            t = TokenCreateRequest(
                label="Guest",
                slug=slug,
                entity_ids=["light.a"],
                expires_in_seconds=3600,
            )
            assert t.slug == slug


class TestTokenUpdateEntitiesRequest:
    def test_valid(self):
        r = TokenUpdateEntitiesRequest(entity_ids=["light.a", "switch.b"])
        assert len(r.entity_ids) == 2

    def test_empty_rejected(self):
        with pytest.raises(ValidationError):
            TokenUpdateEntitiesRequest(entity_ids=[])


class TestTokenUpdateExpiryRequest:
    def test_valid(self):
        r = TokenUpdateExpiryRequest(expires_in_seconds=3600)
        assert r.expires_in_seconds == 3600

    def test_zero_rejected(self):
        with pytest.raises(ValidationError):
            TokenUpdateExpiryRequest(expires_in_seconds=0)


class TestCommandRequest:
    def test_valid_with_data(self):
        r = CommandRequest(
            entity_id="light.living_room",
            service="light.turn_on",
            data={"brightness": 255},
        )
        assert r.data["brightness"] == 255

    def test_valid_without_data(self):
        r = CommandRequest(entity_id="light.living_room", service="turn_off")
        assert r.data == {}

    def test_missing_entity_id(self):
        with pytest.raises(ValidationError):
            CommandRequest(service="turn_on")

    def test_missing_service(self):
        with pytest.raises(ValidationError):
            CommandRequest(entity_id="light.living_room")


class TestAdminLoginRequest:
    def test_valid(self):
        r = AdminLoginRequest(username="admin", password="secret")
        assert r.username == "admin"


def test_never_expires_is_2099():
    """NEVER_EXPIRES_SECONDS matches 2099-12-31T00:00:00Z."""
    assert NEVER_EXPIRES_SECONDS == 4102444800


class TestRecurrenceSchedule:
    def test_valid(self):
        r = RecurrenceSchedule(weekdays=[0, 2], start="09:00", end="13:00")
        assert r.weekdays == [0, 2]

    def test_end_before_start_rejected(self):
        with pytest.raises(ValidationError):
            RecurrenceSchedule(weekdays=[0], start="13:00", end="09:00")

    def test_end_equal_start_rejected(self):
        """Overnight-crossing windows aren't supported — reject rather than misbehave."""
        with pytest.raises(ValidationError):
            RecurrenceSchedule(weekdays=[0], start="09:00", end="09:00")

    def test_weekday_out_of_range_rejected(self):
        with pytest.raises(ValidationError):
            RecurrenceSchedule(weekdays=[7], start="09:00", end="13:00")

    def test_negative_weekday_rejected(self):
        with pytest.raises(ValidationError):
            RecurrenceSchedule(weekdays=[-1], start="09:00", end="13:00")

    def test_empty_weekdays_rejected(self):
        with pytest.raises(ValidationError):
            RecurrenceSchedule(weekdays=[], start="09:00", end="13:00")

    def test_malformed_time_rejected(self):
        with pytest.raises(ValidationError):
            RecurrenceSchedule(weekdays=[0], start="9:00", end="13:00")


class TestTokenCreateRequestScheduling:
    def test_starts_at_and_recurrence_default_none(self):
        """No schedule fields = today's exact behavior (active immediately)."""
        t = TokenCreateRequest(label="Guest", entity_ids=["light.a"], expires_in_seconds=3600)
        assert t.starts_at is None
        assert t.recurrence is None
        assert t.notify_service is None

    def test_valid_with_schedule(self):
        t = TokenCreateRequest(
            label="Guest", entity_ids=["input_button.portal"], expires_in_seconds=3600,
            starts_at=1000,
            recurrence={"weekdays": [1, 3], "start": "09:00", "end": "13:00"},
            notify_service="notify.mobile_app_test",
            notify_lead_seconds=3600,
        )
        assert t.starts_at == 1000
        assert t.recurrence.weekdays == [1, 3]

    def test_notify_lead_without_notify_service_rejected(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="Guest", entity_ids=["light.a"], expires_in_seconds=3600,
                notify_lead_seconds=3600,
            )

    def test_invalid_notify_service_format_rejected(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="Guest", entity_ids=["light.a"], expires_in_seconds=3600,
                notify_service="not-a-notify-service",
            )


class TestTokenUpdateScheduleRequest:
    def test_valid_empty(self):
        r = TokenUpdateScheduleRequest()
        assert r.starts_at is None
        assert r.recurrence is None

    def test_valid_with_values(self):
        r = TokenUpdateScheduleRequest(starts_at=2000, recurrence={"weekdays": [0], "start": "10:00", "end": "11:00"})
        assert r.starts_at == 2000


class TestButtonDomainSupport:
    def test_button_and_input_button_allowed(self):
        assert ALLOWED_SERVICES["button"] == {"press"}
        assert ALLOWED_SERVICES["input_button"] == {"press"}
        assert "button" in SUPPORTED_DOMAINS
        assert "input_button" in SUPPORTED_DOMAINS

    def test_local_only_domains(self):
        assert LOCAL_ONLY_DOMAINS == {"lock", "button", "input_button", "cover"}
        assert "light" not in LOCAL_ONLY_DOMAINS
