"""FIRST EPSS (Exploit Prediction Scoring System) API client."""


def fetch_epss(cve_ids: list[str]) -> list[dict]:
    """Fetch current EPSS scores for the given CVE IDs.

    Args:
        cve_ids: CVE identifiers, e.g. ``["CVE-2024-3094"]``. Batch requests
            to keep the query string within the API's length limits.

    Returns:
        Dicts with ``cve``, ``epss``, ``percentile`` and ``date`` keys.
    """
    raise NotImplementedError
