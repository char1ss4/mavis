"""Load the per-CVE inputs that scoring needs from MySQL. Local only."""
import json
from typing import Any

from mavis.db import get_connection

# One row per stored CVE: KEV status plus its newest EPSS score (rn = 1).
# rn = 1 sits in the ON clause so CVEs with no EPSS row are kept, not filtered out.
_SCORING_INPUTS_QUERY = """
    WITH latest_epss AS (
        SELECT
            cve_id
            , epss
            , percentile
            , score_date
            , ROW_NUMBER() OVER (PARTITION BY cve_id ORDER BY score_date DESC) AS rn
        FROM epss_scores
    )
    SELECT
        c.cve_id
        , c.published
        , c.description
        , c.cvss_score
        , c.cvss_severity
        , (k.cve_id IS NOT NULL)                        AS in_kev
        , k.known_ransomware
        , e.epss
        , e.percentile
        , e.score_date                                  AS epss_date
        , JSON_EXTRACT(c.raw_json, '$.configurations')  AS configurations
    FROM cves c
    LEFT JOIN kev_entries k
        ON k.cve_id = c.cve_id
    LEFT JOIN latest_epss e
        ON e.cve_id = c.cve_id
       AND e.rn = 1
    ORDER BY c.cve_id
    """


def _to_float(value: Any) -> float | None:
    """DECIMAL columns arrive as Decimal; scoring works in plain floats."""
    return None if value is None else float(value)


def parse_scoring_row(row: dict[str, Any]) -> dict[str, Any]:
    """Convert one raw query row into Python types ready for scoring and matching."""
    configurations = row['configurations']
    return {
        **row,
        'cvss_score': _to_float(row['cvss_score']),
        'epss': _to_float(row['epss']),
        'percentile': _to_float(row['percentile']),
        'in_kev': bool(row['in_kev']),
        # NULL until NVD analyses the CVE (~89% of recent ones); [] means "no CPE data"
        'configurations': json.loads(configurations) if configurations else [],
    }


def fetch_scoring_inputs() -> list[dict[str, Any]]:
    """Return every stored CVE with its KEV status and newest EPSS score."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(_SCORING_INPUTS_QUERY)
        return [parse_scoring_row(row) for row in cursor.fetchall()]
    finally:
        cursor.close()
        conn.close()
