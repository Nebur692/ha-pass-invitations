"""Guards for front-end wiring that fails silently rather than loudly."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_tailwind_scans_the_javascript_that_builds_class_names():
    """Class names live in static/domains.js, not only in templates.

    Tailwind only emits the classes it finds in `content`, so leaving the
    scripts out dropped most entity colours from the stylesheet. Nothing
    errored — the shapes just rendered untinted, and only lights kept their
    colour, because that one string also appears in a template. A test is the
    only thing that notices this, since the page still loads and still works.
    """
    config = (ROOT / "tailwind.config.js").read_text(encoding="utf-8")
    content = re.search(r"content:\s*\[(.*?)\]", config, re.S)
    assert content, "tailwind.config.js has no content globs"
    assert "./static/**/*.js" in content.group(1)


def test_every_entity_colour_class_is_reachable_by_tailwind():
    """The colour classes domains.js builds must be somewhere Tailwind scans."""
    domains = (ROOT / "static" / "domains.js").read_text(encoding="utf-8")
    classes = set(re.findall(r"(?:bg|text)-[a-z]+-\d{3}(?:/\d{1,3})?", domains))
    assert classes, "no colour classes found — did domains.js move?"

    config = (ROOT / "tailwind.config.js").read_text(encoding="utf-8")
    content = re.search(r"content:\s*\[(.*?)\]", config, re.S).group(1)
    # Every one of them is written in this file, so the glob covering it is
    # what makes them all reachable.
    assert "./static/**/*.js" in content
