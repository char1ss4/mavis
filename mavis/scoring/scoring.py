"""Risk scoring for CVEs against the local watchlist."""


def score_cve(
    cvss_score: float | None,
    epss: float | None,
    in_kev: bool,
    watchlist_match: bool,
) -> float:
    """Compute a composite priority score for a single CVE.

    A missing CVSS score (common for freshly published CVEs awaiting NVD
    analysis) must be treated as a neutral mid-range value, not zero, so that
    unscored CVEs are not silently ranked below everything else.

    Args:
        cvss_score: CVSS base score (0.0-10.0), or None if not yet assigned.
        epss: EPSS probability (0.0-1.0), or None if unavailable.
        in_kev: Whether the CVE is in the CISA KEV catalog.
        watchlist_match: Whether the CVE matches an entry in the local watchlist.

    Returns:
        The composite score (higher = more urgent).
    """
    raise NotImplementedError
