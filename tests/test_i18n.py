"""Tests for app/i18n.py: Accept-Language detection and string tables."""
import re
import time

import pytest

from app import database as db
from app import i18n


# ---------------------------------------------------------------------------
# Pure detection logic
# ---------------------------------------------------------------------------

def test_detect_lang_prefers_spanish_when_first():
    assert i18n.detect_lang("es-ES,es;q=0.9,en;q=0.8") == "es"


def test_detect_lang_prefers_english_when_first():
    assert i18n.detect_lang("en-US,en;q=0.9,es;q=0.8") == "en"


def test_detect_lang_respects_quality_order():
    # es has lower q than en here despite appearing first
    assert i18n.detect_lang("es;q=0.5, en;q=0.9") == "en"


def test_detect_lang_unsupported_language_falls_back_to_default():
    assert i18n.detect_lang("zh-CN,zh;q=0.9,ja;q=0.8") == "en"


def test_detect_lang_missing_header_falls_back_to_default():
    assert i18n.detect_lang(None) == "en"
    assert i18n.detect_lang("") == "en"


def test_detect_lang_malformed_quality_value_does_not_crash():
    assert i18n.detect_lang("es;q=bogus,en;q=0.9") in ("es", "en")


# ---------------------------------------------------------------------------
# String tables
# ---------------------------------------------------------------------------

def test_admin_tables_have_matching_keys_across_languages():
    assert set(i18n.ADMIN_SUPPORTED_LANGS) == {"en", "es"}
    assert set(i18n.ADMIN_STRINGS["en"]) == set(i18n.ADMIN_STRINGS["es"])


def test_guest_supported_langs_are_the_24_official_eu_languages():
    # ISO 639-1 codes for the 24 official languages of the European Union.
    assert set(i18n.GUEST_SUPPORTED_LANGS) == {
        "bg", "hr", "cs", "da", "nl", "en", "et", "fi", "fr", "de", "el",
        "hu", "ga", "it", "lv", "lt", "mt", "pl", "pt", "ro", "sk", "sl",
        "es", "sv",
    }


def test_guest_tables_have_matching_keys_across_all_24_languages():
    """Every language HAPass ships for the guest PWA must define the exact
    same set of keys as English — a missing/misspelled key would silently
    fall back to English at runtime (see make_t), which this test would
    otherwise never catch."""
    en_keys = set(i18n.GUEST_STRINGS["en"])
    for lang in i18n.GUEST_SUPPORTED_LANGS:
        assert lang in i18n.GUEST_STRINGS, f"missing GUEST_STRINGS table for {lang!r}"
        assert set(i18n.GUEST_STRINGS[lang]) == en_keys, f"key mismatch for {lang!r}"


def test_guest_table_placeholders_match_english_in_every_language():
    """{t}/{u}/{h}/{name}-style placeholders must survive translation
    verbatim — a dropped or renamed placeholder would raise/format wrong
    at runtime instead of failing a test."""
    for key, en_value in i18n.GUEST_STRINGS["en"].items():
        en_placeholders = set(re.findall(r"\{(\w+)\}", en_value))
        if not en_placeholders:
            continue
        for lang in i18n.GUEST_SUPPORTED_LANGS:
            value = i18n.GUEST_STRINGS[lang][key]
            got = set(re.findall(r"\{(\w+)\}", value))
            assert got == en_placeholders, f"{lang}.{key}: expected {en_placeholders}, got {got}"


def test_make_t_substitutes_placeholders():
    t = i18n.make_t(i18n.ADMIN_STRINGS, "en")
    assert t("entities_count", n=3) == "3 entities"
    t_es = i18n.make_t(i18n.ADMIN_STRINGS, "es")
    assert t_es("entities_count", n=3) == "3 entidades"


def test_make_t_falls_back_to_english_for_unknown_key():
    t = i18n.make_t(i18n.ADMIN_STRINGS, "es")
    assert t("this_key_does_not_exist") == "this_key_does_not_exist"


# ---------------------------------------------------------------------------
# End-to-end: guest PWA honors Accept-Language, admin honors cookie override
# ---------------------------------------------------------------------------

async def test_guest_pwa_defaults_to_english(client, mock_ha_client, test_db):
    now = int(time.time())
    await db.create_token(
        label="Guest", slug="lang-test-en", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.get("/g/lang-test-en")
    assert resp.status_code == 200
    assert 'lang="en"' in resp.text


async def test_guest_pwa_auto_detects_spanish(client, mock_ha_client, test_db):
    now = int(time.time())
    await db.create_token(
        label="Guest", slug="lang-test-es", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.get("/g/lang-test-es", headers={"Accept-Language": "es-ES,es;q=0.9"})
    assert resp.status_code == 200
    assert 'lang="es"' in resp.text


async def test_guest_pwa_auto_detects_a_new_eu_language(client, mock_ha_client, test_db):
    """Spot-check one of the 22 languages added alongside EN/ES, end-to-end."""
    now = int(time.time())
    await db.create_token(
        label="Guest", slug="lang-test-fr", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.get("/g/lang-test-fr", headers={"Accept-Language": "fr-FR,fr;q=0.9"})
    assert resp.status_code == 200
    assert 'lang="fr"' in resp.text


async def test_guest_pwa_has_no_language_override_mechanism(client, mock_ha_client, test_db):
    """Unlike the admin dashboard, the guest PWA is always auto-detected —
    there's no cookie/profile for a guest to configure. A stray admin-lang
    cookie must not leak into the guest response."""
    now = int(time.time())
    await db.create_token(
        label="Guest", slug="lang-test-no-override", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.get(
        "/g/lang-test-no-override",
        headers={"Accept-Language": "en-US"},
        cookies={i18n.ADMIN_LANG_COOKIE: "es"},
    )
    assert resp.status_code == 200
    assert 'lang="en"' in resp.text
