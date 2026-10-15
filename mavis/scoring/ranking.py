"""Rank stored CVEs by local priority. Shared by `score` and `brief`; local only."""
from typing import Any

from mavis.scoring.scoring import score_cve
from mavis.scoring.watchlist import match_cve


def rank_cves(rows: list[dict[str, Any]], watchlist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Match and score each CVE, highest score first.

    Args:
        rows: Rows from :func:`mavis.scoring.inputs.fetch_scoring_inputs`.
        watchlist: Entries from :func:`mavis.scoring.watchlist.load_watchlist`.

    Returns:
        Copies of the rows with ``matches`` (matching watchlist entries),
        ``match_type`` (``"cpe"``, ``"keyword"`` or None) and ``score`` added.
    """
    ranked: list[dict[str, Any]] = []
    for row in rows:
        matches = match_cve(row, watchlist)
        # match_cve uses either CPE or keywords for a CVE, never both, so all
        # matches share one type; several matches don't add up to more points
        match_type = matches[0]['match_type'] if matches else None
        ranked.append({
            **row,
            'matches': matches,
            'match_type': match_type,
            'score': score_cve(row['cvss_score'], row['epss'], row['in_kev'], match_type),
        })
    # sort is stable, so equal scores keep the input (CVE ID) order
    ranked.sort(key=lambda r: r['score'], reverse=True)
    return ranked
