"""Local watchlist of software you run. Never leaves the machine."""

from typing import Any


def load_watchlist(path: str = "watchlist.yaml") -> list[dict[str, Any]]:
    """Load watchlist entries from a YAML file.

    Args:
        path: Path to the local watchlist (see watchlist.example.yaml).

    Returns:
        Watchlist entries as dicts.
    """
    raise NotImplementedError


def match_cve(cve: dict[str, Any], watchlist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the watchlist entries that a CVE affects.

    Args:
        cve: A CVE record (NVD format).
        watchlist: Entries returned by :func:`load_watchlist`.

    Returns:
        Matching watchlist entries; empty if none match.
    """
    raise NotImplementedError
