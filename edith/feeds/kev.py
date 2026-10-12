"""CISA Known Exploited Vulnerabilities (KEV) catalog client."""


def fetch_kev() -> list[dict]:
    """Download the full CISA KEV catalog.

    Returns:
        KEV entries (the ``vulnerabilities`` array of the JSON feed) as dicts.
    """
    raise NotImplementedError
