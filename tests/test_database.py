"""Tests for database CRUD operations."""
import json
import time

import pytest

from app import database as db


# ---------------------------------------------------------------------------
# Admin sessions
# ---------------------------------------------------------------------------

async def test_create_admin_session(test_db):
    session_id = await db.create_admin_session(ttl_seconds=3600)
    assert len(session_id) == 64  # two uuid4.hex concatenated


async def test_get_valid_admin_session(test_db):
    session_id = await db.create_admin_session(ttl_seconds=3600)
    row = await db.get_admin_session(session_id)
    assert row is not None
    assert row["id"] == session_id


async def test_get_expired_admin_session_returns_none(test_db):
    session_id = await db.create_admin_session(ttl_seconds=0)
    # Expiry is now + 0 = now, and the query checks expires_at > now
    # So with ttl=0, it may or may not be expired depending on timing.
    # Use ttl=-1 via direct insert to guarantee expiry.
    conn = await db.get_db()
    now = int(time.time())
    await conn.execute(
        "INSERT INTO admin_sessions (id, created_at, expires_at) VALUES (?, ?, ?)",
        ("expired-session", now - 100, now - 1),
    )
    await conn.commit()
    row = await db.get_admin_session("expired-session")
    assert row is None


async def test_delete_admin_session(test_db):
    session_id = await db.create_admin_session(ttl_seconds=3600)
    await db.delete_admin_session(session_id)
    row = await db.get_admin_session(session_id)
    assert row is None


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

async def test_create_token(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test",
        slug="test-slug",
        entity_ids=["light.a"],
        expires_at=now + 3600,
        ip_allowlist=None,
    )
    assert token["slug"] == "test-slug"
    assert token["label"] == "Test"
    assert token["revoked"] == 0


async def test_get_token_by_slug(test_db):
    now = int(time.time())
    await db.create_token(
        label="Test", slug="by-slug", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    row = await db.get_token_by_slug("by-slug")
    assert row is not None
    assert row["slug"] == "by-slug"


async def test_get_token_by_id(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="by-id", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    row = await db.get_token_by_id(token["id"])
    assert row is not None
    assert row["id"] == token["id"]


async def test_list_tokens_with_entity_count(test_db):
    now = int(time.time())
    await db.create_token(
        label="Multi", slug="multi", entity_ids=["light.a", "switch.b", "fan.c"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    rows = await db.list_tokens()
    assert len(rows) == 1
    assert rows[0]["entity_count"] == 3


async def test_update_token_entities(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="upd-ent", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.update_token_entities(token["id"], ["switch.b", "fan.c"])
    entities = await db.get_token_entities(token["id"])
    assert set(entities) == {"switch.b", "fan.c"}


async def test_update_token_expiry(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="upd-exp", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    new_expiry = now + 7200
    await db.update_token_expiry(token["id"], new_expiry)
    row = await db.get_token_by_id(token["id"])
    assert row["expires_at"] == new_expiry


async def test_revoke_token(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="rev", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.revoke_token(token["id"])
    row = await db.get_token_by_id(token["id"])
    assert row["revoked"] == 1


async def test_hard_delete_cascades(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="hard-del", entity_ids=["light.a", "switch.b"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    tid = token["id"]
    await db.delete_token(tid)
    assert await db.get_token_by_id(tid) is None
    # Entities should be cascade-deleted
    entities = await db.get_token_entities(tid)
    assert entities == []


async def test_touch_updates_last_accessed(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="touch", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    assert token["last_accessed"] is None
    await db.touch_token(token["id"])
    row = await db.get_token_by_id(token["id"])
    assert row["last_accessed"] is not None
    assert row["last_accessed"] >= now


async def test_entity_deduplication(test_db):
    """Duplicate entity_ids in create should be stored once."""
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="dedup", entity_ids=["light.a", "light.a", "light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    entities = await db.get_token_entities(token["id"])
    assert entities == ["light.a"]


# ---------------------------------------------------------------------------
# Access log
# ---------------------------------------------------------------------------

async def test_log_access_inserts_row(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="log-test", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.log_access(
        token_id=token["id"],
        event_type="command",
        ip_address="192.168.1.100",
        user_agent="TestAgent/1.0",
        entity_id="light.a",
        service="light.turn_on",
    )
    conn = await db.get_db()
    async with conn.execute(
        "SELECT * FROM access_log WHERE token_id = ?", (token["id"],)
    ) as cur:
        row = await cur.fetchone()
    assert row is not None
    assert row["event_type"] == "command"
    assert row["ip_address"] == "192.168.1.100"
    assert row["entity_id"] == "light.a"
    assert row["service"] == "light.turn_on"


async def test_list_access_logs_returns_newest_with_token_label(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Guest",
        slug="activity-list",
        entity_ids=["light.a"],
        expires_at=now + 3600,
        ip_allowlist=None,
    )
    await db.log_access(token["id"], event_type="page_load")
    await db.log_access(
        token["id"],
        event_type="command",
        entity_id="light.a",
        service="light.turn_on",
    )

    rows = await db.list_access_logs(limit=1)

    assert len(rows) == 1
    assert rows[0]["event_type"] == "command"
    assert rows[0]["token_label"] == "Guest"
    assert rows[0]["entity_id"] == "light.a"
    assert rows[0]["service"] == "light.turn_on"


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

async def test_cleanup_removes_old_access_logs(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="cleanup-log", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    conn = await db.get_db()
    # Insert an old log entry (100 days ago)
    await conn.execute(
        "INSERT INTO access_log (token_id, timestamp, event_type) VALUES (?, ?, ?)",
        (token["id"], now - 100 * 86400, "command"),
    )
    await conn.commit()

    await db.cleanup_old_data(retention_days=90)

    async with conn.execute("SELECT COUNT(*) as cnt FROM access_log") as cur:
        row = await cur.fetchone()
    assert row["cnt"] == 0


async def test_cleanup_removes_expired_admin_sessions(test_db):
    conn = await db.get_db()
    now = int(time.time())
    await conn.execute(
        "INSERT INTO admin_sessions (id, created_at, expires_at) VALUES (?, ?, ?)",
        ("old-session", now - 200, now - 100),
    )
    await conn.commit()

    await db.cleanup_old_data(retention_days=90)

    async with conn.execute(
        "SELECT * FROM admin_sessions WHERE id = 'old-session'"
    ) as cur:
        row = await cur.fetchone()
    assert row is None


async def test_cleanup_does_not_delete_expired_or_revoked_tokens(test_db):
    """Guest tokens are retained so admins can renew or delete them explicitly."""
    now = int(time.time())
    expired = await db.create_token(
        label="Expired", slug="expired-cleanup", entity_ids=["light.a"],
        expires_at=now - 60, ip_allowlist=None,
    )
    revoked = await db.create_token(
        label="Revoked", slug="revoked-cleanup", entity_ids=["switch.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.revoke_token(revoked["id"])

    await db.cleanup_old_data(retention_days=1)

    assert await db.get_token_by_id(expired["id"]) is not None
    row = await db.get_token_by_id(revoked["id"])
    assert row is not None
    assert row["revoked"] == 1


# ---------------------------------------------------------------------------
# Scheduling, notify, and binding (see migrations/versions/003_scheduling.py)
# ---------------------------------------------------------------------------

async def test_create_token_with_schedule_fields(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Scheduled", slug="scheduled", entity_ids=["input_button.portal"],
        expires_at=now + 3600, ip_allowlist=None,
        starts_at=now + 100,
        recurrence={"weekdays": [1, 3], "start": "09:00", "end": "13:00"},
        notify_service="notify.mobile_app_test",
        notify_lead_seconds=1800,
    )
    assert token["starts_at"] == now + 100
    assert json.loads(token["recurrence"]) == {"weekdays": [1, 3], "start": "09:00", "end": "13:00"}
    assert token["notify_service"] == "notify.mobile_app_test"
    assert token["notify_lead_seconds"] == 1800
    assert token["notify_sent"] == 0


async def test_create_token_without_schedule_fields_defaults_none(test_db):
    """Backward compatibility: no schedule fields = today's exact behavior."""
    now = int(time.time())
    token = await db.create_token(
        label="Plain", slug="plain", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    assert token["starts_at"] is None
    assert token["recurrence"] is None
    assert token["bound_secret"] is None


async def test_update_token_schedule(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="upd-sched", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.update_token_schedule(
        token["id"], starts_at=now + 500,
        recurrence={"weekdays": [0], "start": "10:00", "end": "11:00"},
    )
    row = await db.get_token_by_id(token["id"])
    assert row["starts_at"] == now + 500
    assert json.loads(row["recurrence"]) == {"weekdays": [0], "start": "10:00", "end": "11:00"}


async def test_mark_notify_sent(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="notify-sent", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None, notify_service="notify.x",
    )
    await db.mark_notify_sent(token["id"])
    row = await db.get_token_by_id(token["id"])
    assert row["notify_sent"] == 1


async def test_list_tokens_pending_notify(test_db):
    now = int(time.time())
    due = await db.create_token(
        label="Due", slug="due-notify", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
        starts_at=now + 100, notify_service="notify.x", notify_lead_seconds=200,
    )
    not_due = await db.create_token(
        label="NotDue", slug="not-due-notify", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
        starts_at=now + 10000, notify_service="notify.x", notify_lead_seconds=200,
    )
    no_notify = await db.create_token(
        label="NoNotify", slug="no-notify", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
        starts_at=now + 100,
    )

    pending = await db.list_tokens_pending_notify(now)
    pending_ids = {r["id"] for r in pending}
    assert due["id"] in pending_ids
    assert not_due["id"] not in pending_ids
    assert no_notify["id"] not in pending_ids

    await db.mark_notify_sent(due["id"])
    pending_after = await db.list_tokens_pending_notify(now)
    assert due["id"] not in {r["id"] for r in pending_after}


async def test_claim_token_binding(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="claim-me", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.claim_token_binding(token["id"], "secretA", now)
    row = await db.get_token_by_id(token["id"])
    assert row["bound_secret"] == "secretA"
    assert row["bound_claimed_at"] == now


async def test_claim_token_binding_race_safe(test_db):
    """A second claim attempt must not overwrite an already-bound secret."""
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="claim-race", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.claim_token_binding(token["id"], "secretA", now)
    await db.claim_token_binding(token["id"], "secretB", now + 1)
    row = await db.get_token_by_id(token["id"])
    assert row["bound_secret"] == "secretA"


async def test_unbind_token(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="unbind-me", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.claim_token_binding(token["id"], "secretA", now)
    await db.unbind_token(token["id"])
    row = await db.get_token_by_id(token["id"])
    assert row["bound_secret"] is None
    assert row["bound_claimed_at"] is None
