"""Country-based access allowlist.

Resolves ISO 3166-1 alpha-2 country codes (e.g. "ES") into their known
public IP ranges, using the free, no-signup zone files published by
ipdeny.com (https://www.ipdeny.com/ipblocks/), so the existing CIDR-based
enforcement in app/routers/guest.py (_ip_in_cidrs) can be reused unchanged.

Deliberately NOT a MaxMind GeoLite2/mmdb setup: that requires a free account
+ license key just to download the database, and periodic re-downloads to
stay current. ipdeny's per-country zone files need no registration and are
plain text (one CIDR per line), which is a better fit for a small
self-hosted add-on.

Zone files are cached to disk (default 30 days) so normal operation never
depends on ipdeny being reachable — only the *first* time a given country
is used, or once the cache goes stale, does this hit the network.
"""
import logging
import time
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

ZONE_URL = "https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone"
CACHE_DIR = Path("/data/geoip_cache")
CACHE_MAX_AGE_SECONDS = 30 * 24 * 3600  # ipdeny updates its lists periodically; no need to refetch every request

# ISO 3166-1 alpha-2 codes. Validated against this so a typo produces a clear
# 422 at creation time instead of silently resolving to an empty CIDR list —
# an empty list makes app.routers.guest._ip_in_cidrs() reject *every* IP,
# which would make the link inaccessible to everyone rather than failing loudly.
ISO_3166_1_ALPHA2 = {
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
    "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
    "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
    "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
    "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
    "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
    "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
    "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
    "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
    "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
}


class CountryResolutionError(Exception):
    """Raised when a country's IP ranges can't be resolved (invalid code, or
    no cache and ipdeny is unreachable)."""


def _cache_path(cc: str) -> Path:
    return CACHE_DIR / f"{cc}.zone"


async def _fetch_zone(cc: str) -> list[str]:
    url = ZONE_URL.format(cc=cc)
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        resp.raise_for_status()
    lines = [line.strip() for line in resp.text.splitlines()]
    return [line for line in lines if line and not line.startswith("#")]


async def get_country_cidrs(country_code: str) -> list[str]:
    """Returns the cached (or freshly fetched) list of CIDR blocks for one
    ISO 3166-1 alpha-2 country code. Raises CountryResolutionError if the
    code is invalid, or if fetching is needed but fails with no usable cache."""
    cc = country_code.strip().lower()
    if cc.upper() not in ISO_3166_1_ALPHA2:
        raise CountryResolutionError(f"Not a valid ISO 3166-1 alpha-2 country code: {country_code!r}")

    cache_file = _cache_path(cc)
    if cache_file.exists():
        age = time.time() - cache_file.stat().st_mtime
        if age < CACHE_MAX_AGE_SECONDS:
            return [line for line in cache_file.read_text().splitlines() if line]

    try:
        cidrs = await _fetch_zone(cc)
    except Exception as exc:
        if cache_file.exists():
            logger.warning("Could not refresh IP ranges for %s (%s) — using stale cache", cc.upper(), exc)
            return [line for line in cache_file.read_text().splitlines() if line]
        raise CountryResolutionError(
            f"Could not fetch IP ranges for {cc.upper()} and no cached copy exists yet"
        ) from exc

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("\n".join(cidrs))
    return cidrs


async def resolve_countries_to_cidrs(country_codes: list[str]) -> list[str]:
    """Resolves a list of country codes into the combined, de-duplicated
    list of CIDR blocks covering all of them."""
    seen: dict[str, None] = {}
    for code in country_codes:
        for cidr in await get_country_cidrs(code):
            seen[cidr] = None
    return list(seen)
