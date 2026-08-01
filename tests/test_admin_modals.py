"""Every modal must be closable by all three routes the dashboard offers.

Adding a modal means registering it in three separate places in the template.
Missing one is silent — the dialog opens and then traps you, which is exactly
what shipped in v1.5.0 for the presence panel: the backdrop was registered, the
close buttons and the Escape key were not.
"""
import pathlib
import re

TEMPLATE = pathlib.Path(__file__).resolve().parents[1] / "templates" / "admin_dashboard.html"
HTML = TEMPLATE.read_text(encoding="utf-8")


def _declared_modals() -> set[str]:
    """Modal names that exist as markup: id="presence-modal" -> "presence"."""
    return set(re.findall(r'id="([a-z-]+)-modal"', HTML))


def _button_targets() -> set[str]:
    """Names used by close buttons, e.g. data-modal="presence"."""
    return set(re.findall(r'data-action="close-modal"\s+data-modal="([a-z-]+)"', HTML))


def _closer_map_keys() -> set[str]:
    """Keys of the modalMap the click dispatcher looks the closer up in."""
    block = re.search(r"const modalMap = \{(.+?)\};", HTML, re.S).group(1)
    return set(re.findall(r"(\w+):", block))


def _escape_closer_ids() -> set[str]:
    block = re.search(r"const closers = \{(.+?)\};", HTML, re.S).group(1)
    return {m.removesuffix("-modal") for m in re.findall(r"'([a-z-]+-modal)'", block)}


def _backdrop_ids() -> set[str]:
    block = re.search(r"\[([^\]]*'-modal'[^\]]*|[^\]]*-modal'[^\]]*)\]\.forEach", HTML).group(1)
    return {m.removesuffix("-modal") for m in re.findall(r"'([a-z-]+-modal)'", block)}


def test_every_close_button_has_a_closer_in_the_dispatcher():
    missing = _button_targets() - _closer_map_keys()
    assert not missing, f"close buttons that do nothing: {sorted(missing)}"


def test_every_modal_closes_with_escape():
    missing = _button_targets() - _escape_closer_ids()
    assert not missing, f"modals Escape cannot close: {sorted(missing)}"


def test_every_modal_closes_by_clicking_the_backdrop():
    missing = _button_targets() - _backdrop_ids()
    assert not missing, f"modals the backdrop cannot close: {sorted(missing)}"


def test_the_presence_panel_is_among_the_modals_checked():
    """Guards the guard: if the regexes stop matching, these tests would pass
    vacuously and catch nothing."""
    assert "presence" in _button_targets()
    assert "presence" in _declared_modals()
    assert len(_button_targets()) >= 6
