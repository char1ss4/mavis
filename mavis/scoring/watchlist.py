"""Local watchlist of software you run. Never leaves the machine."""
import re
from typing import Any

import yaml


def load_watchlist(path: str = "watchlist.yaml") -> list[dict[str, Any]]:
    """Load watchlist entries from a YAML file.

    Args:
        path: Path to the local watchlist (format: see "Watchlist" in README.md).

    Returns:
        Watchlist entries as dicts.
    """
    with open(path, encoding='utf-8') as f:
        data = yaml.safe_load(f) or {}

    entries = data.get('watchlist') or []
    for entry in entries:
        name = entry.get('name', '(unnamed)')
        if not entry.get('vendor') or not entry.get('product'):
            raise ValueError(f"Watchlist entry {name!r} needs a vendor and product")
        keywords = entry.get('keywords')
        if keywords is not None and (
            not isinstance(keywords, list) or not all(isinstance(k, str) and k for k in keywords)
        ):
            raise ValueError(f"Watchlist entry {name!r}: keywords must be a list of phrases")
    return entries


ANY_PRODUCT = '*'


def _keywords(entry: dict[str, Any]) -> list[str]:
    """Phrases to look for in descriptions; defaults to the product (or vendor) name."""
    if entry.get('keywords'):
        return entry['keywords']
    # A vendor-wide entry has no product name to search for, so use the vendor's
    name = entry['vendor'] if entry['product'] == ANY_PRODUCT else entry['product']
    # CPE names use underscores (http_server) where descriptions use spaces
    return [name.replace('_', ' ')]


def _cpe_matches(entry: dict[str, Any], pairs: set[tuple[str, str]]) -> bool:
    """Whether an entry matches a CVE's (vendor, product) pairs; product ``*`` means any."""
    vendor, product = entry['vendor'].lower(), entry['product'].lower()
    if product == ANY_PRODUCT:
        return any(v == vendor for v, _ in pairs)
    return (vendor, product) in pairs


def _mentions(description: str, phrase: str) -> bool:
    """Whole-phrase, case-insensitive search that also rejects hyphenated names.

    ``\\b`` treats ``-`` as a boundary, so ``flask`` would match "Flask-Multipass";
    the lookarounds require no letter, digit, ``_`` or ``-`` on either side.
    """
    return re.search(rf"(?<![\w-]){re.escape(phrase)}(?![\w-])", description, re.IGNORECASE) is not None


def _cpe_vendor_products(configurations: list[dict[str, Any]]) -> set[tuple[str, str]]:
    """Collect (vendor, product) pairs from a CVE's vulnerable CPE matches."""
    pairs: set[tuple[str, str]] = set()
    for config in configurations:
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                # vulnerable: false marks a platform condition (e.g. the OS an app runs on)
                if not match.get('vulnerable', True):
                    continue
                # cpe:2.3:part:vendor:product:version:...
                parts = match.get('criteria', '').split(':')
                if len(parts) > 4:
                    pairs.add((parts[3].lower(), parts[4].lower()))
    return pairs


def match_cve(cve: dict[str, Any], watchlist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the watchlist entries that a CVE affects.

    Matches on CPE vendor and product when NVD has analysed the CVE
    (``product: "*"`` matches any product from that vendor). Most
    recent CVEs have no CPE data yet, so those fall back to searching the
    description for the entry's ``keywords`` (default: the product name).
    Keyword matches are less certain: descriptions often mention a product
    as context ("a fork of MySQL"), so specific phrases work better.

    Args:
        cve: A row from :func:`mavis.scoring.inputs.fetch_scoring_inputs`
            (``configurations`` in NVD's format, plus the English ``description``).
        watchlist: Entries returned by :func:`load_watchlist`.

    Returns:
        Matching watchlist entries, each with a ``match_type`` of ``"cpe"`` or
        ``"keyword"``; empty if none match.
    """
    configurations = cve.get('configurations') or []
    if configurations:
        # Once NVD has analysed a CVE its CPE list is authoritative: no keyword fallback
        pairs = _cpe_vendor_products(configurations)
        return [
            {**entry, 'match_type': 'cpe'}
            for entry in watchlist
            if _cpe_matches(entry, pairs)
        ]

    description = cve.get('description') or ''
    return [
        {**entry, 'match_type': 'keyword'}
        for entry in watchlist
        if any(_mentions(description, phrase) for phrase in _keywords(entry))
    ]
