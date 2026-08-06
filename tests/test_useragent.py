"""Turning a User-Agent into something an admin recognises at a glance."""
from app import useragent


def test_real_agents_seen_in_production():
    # The two devices in the incident that made this column necessary: a link
    # paired from an iPhone, and the admin's own Android being refused.
    assert useragent.describe(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1"
    ) == "iPhone · Safari"
    assert useragent.describe(
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/150.0.0.0 Mobile Safari/537.36 EdgA/150.0.0.0"
    ) == "Android · Edge"


def test_a_chat_app_fetcher_is_named_outright():
    """A link held by one of these is the bug this whole column exists for."""
    assert useragent.describe("WhatsApp/2.23.20.0") == "WhatsApp"
    assert useragent.describe("TelegramBot (like TwitterBot)") == "Telegram"


def test_more_specific_token_wins_over_the_ones_it_contains():
    # Every Android browser also says Linux, Edge also says Chrome, and Chrome
    # also says Safari — so ordering is the whole game here.
    assert useragent.describe(
        "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 Safari/537.36"
    ) == "Android · Chrome"
    assert useragent.describe(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 "
        "Safari/537.36 Edg/120"
    ) == "Windows · Edge"


def test_nothing_recognisable_is_not_invented():
    assert useragent.describe(None) is None
    assert useragent.describe("") is None
    assert useragent.describe("   ") is None


def test_an_unknown_agent_is_trimmed_rather_than_dropped():
    """Two odd devices still have to be distinguishable from each other."""
    described = useragent.describe("x" * 200)
    assert described is not None
    assert len(described) <= useragent.MAX_LENGTH
