"""Turn a User-Agent header into something an admin can recognise.

The panel used to say only "paired 8h ago", which is not enough to answer the
one question an admin actually asks — *is that my guest's phone, or did I claim
the link myself while testing it?* Answering that meant reading the database.

Deliberately crude. User-Agent strings are self-reported and endlessly
irregular, so this aims at "recognisable at a glance", never at precision, and
returns None rather than guessing when nothing matches.
"""

# Order matters: the first match wins, and the strings overlap heavily. Every
# Android browser also says "Linux", Edge also says "Chrome", and Chrome also
# says "Safari", so the more specific token has to be tested first.
_PLATFORMS = (
    ("iPhone", "iPhone"),
    ("iPad", "iPad"),
    ("Android", "Android"),
    ("Windows", "Windows"),
    ("Macintosh", "Mac"),
    ("Mac OS X", "Mac"),
    ("CrOS", "ChromeOS"),
    ("Linux", "Linux"),
)

_BROWSERS = (
    ("EdgA/", "Edge"),
    ("Edg/", "Edge"),
    ("OPR/", "Opera"),
    ("SamsungBrowser/", "Samsung Internet"),
    ("FxiOS/", "Firefox"),
    ("Firefox/", "Firefox"),
    ("CriOS/", "Chrome"),
    ("Chrome/", "Chrome"),
    ("Safari/", "Safari"),
)

# Things that are not a person's browser at all. Worth naming outright: a link
# claimed by one of these is the bug that made this column necessary.
_AGENTS = (
    ("WhatsApp", "WhatsApp"),
    ("TelegramBot", "Telegram"),
    ("Discordbot", "Discord"),
    ("Slackbot", "Slack"),
    ("facebookexternalhit", "Facebook"),
    ("Twitterbot", "X/Twitter"),
    ("SkypeUriPreview", "Skype"),
    ("Applebot", "Apple"),
)

MAX_LENGTH = 40


def describe(user_agent: str | None) -> str | None:
    """A short, human-recognisable label, or None if nothing is recognisable."""
    if not user_agent:
        return None
    ua = user_agent.strip()
    if not ua:
        return None

    for token, name in _AGENTS:
        if token.lower() in ua.lower():
            return name

    platform = next((name for token, name in _PLATFORMS if token in ua), None)
    browser = next((name for token, name in _BROWSERS if token in ua), None)

    if platform and browser:
        return f"{platform} · {browser}"
    if platform or browser:
        return platform or browser
    # Something unrecognised: show a trimmed version rather than nothing, so an
    # admin can still tell two different devices apart.
    return ua[:MAX_LENGTH]
