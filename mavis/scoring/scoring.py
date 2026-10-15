"""Risk scoring for CVEs against the local watchlist."""
import math

# Points out of 100. A starting judgement, kept as constants so they're easy to tune:
# CVSS spreads out the long tail of ordinary CVEs, EPSS separates the likely-exploited
# few, KEV and the watchlist are yes/no bonuses.
CVSS_WEIGHT = 35
EPSS_WEIGHT = 25
KEV_POINTS = 20
WATCHLIST_POINTS = {'cpe': 20, 'keyword': 10}  # keyword matches are less certain

# Midpoint of the 0-10 scale, so unscored CVEs land mid-table rather than last
NEUTRAL_CVSS = 5.0


def score_cve(
    cvss_score: float | None,
    epss: float | None,
    in_kev: bool,
    watchlist_match: str | None,
) -> float:
    """Compute a composite priority score for a single CVE.

    A missing CVSS score (common for freshly published CVEs awaiting NVD
    analysis) must be treated as a neutral mid-range value, not zero, so that
    unscored CVEs are not silently ranked below everything else.

    A missing EPSS score counts as 0: it's missing mainly for brand-new CVEs,
    and the typical EPSS is close to 0 anyway. EPSS goes through a square root
    because most scores are tiny (median ~0.001) and would otherwise all
    contribute nothing.

    Args:
        cvss_score: CVSS base score (0.0-10.0), or None if not yet assigned.
        epss: EPSS probability (0.0-1.0), or None if unavailable.
        in_kev: Whether the CVE is in the CISA KEV catalog.
        watchlist_match: How the CVE matched the local watchlist: ``"cpe"``,
            ``"keyword"`` (half the points), or None for no match.

    Returns:
        The composite score from 0 to 100 (higher = more urgent).
    """
    cvss = NEUTRAL_CVSS if cvss_score is None else cvss_score
    score = cvss / 10 * CVSS_WEIGHT
    score += math.sqrt(epss or 0.0) * EPSS_WEIGHT
    if in_kev:
        score += KEV_POINTS
    if watchlist_match is not None:
        score += WATCHLIST_POINTS[watchlist_match]
    return round(score, 1)
