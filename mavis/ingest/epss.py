"""FIRST EPSS (Exploit Prediction Scoring System) API client."""
import datetime
import time

# config must be imported before any network I/O (loads .env, OS trust store)
from mavis import config
import requests

from mavis.db import get_connection

EPSS_URL = "https://api.first.org/data/v1/epss"
# The API returns at most 100 results per page and caps the URL at ~2000
# characters; 50 IDs (~900 chars once the commas are encoded) stays well inside both.
BATCH_SIZE = 50
MAX_RETRIES = 5


def _get_with_retry(params: dict) -> dict:
    """GET one batch from EPSS, backing off and retrying on 429/503."""
    wait = 2
    for attempt in range(MAX_RETRIES):
        response = requests.get(
            EPSS_URL, params=params, headers={'User-Agent': 'MAVIS EPSS Client'}, timeout=30,
        )

        # 429 = over FIRST's rate limit, 503 = temporarily unavailable
        if response.status_code not in (429, 503):
            response.raise_for_status()
            return response.json()

        if attempt < MAX_RETRIES - 1:
            time.sleep(wait)
            wait *= 2  # 2s, 4s, 8s, 16s

    raise RuntimeError(
        f"EPSS still returning HTTP {response.status_code} after {MAX_RETRIES} attempts"
    )


def fetch_epss(cve_ids: list[str]) -> list[dict]:
    """Fetch current EPSS scores for the given CVE IDs.

    Args:
        cve_ids: CVE identifiers, e.g. ``["CVE-2024-3094"]``. Batch requests
            to keep the query string within the API's length limits.

    Returns:
        Dicts with ``cve``, ``epss``, ``percentile`` and ``date`` keys.
    """
    results = []
    for i in range(0, len(cve_ids), BATCH_SIZE):
        batch = cve_ids[i:i + BATCH_SIZE]
        data = _get_with_retry({'cve': ','.join(batch), 'limit': BATCH_SIZE})
        # CVEs EPSS hasn't scored yet (often brand-new ones) are simply absent
        results.extend(data.get('data', []))
    return results


def parse_epss(item: dict) -> dict:
    """Convert one EPSS API item into a row for the ``epss_scores`` table."""
    # The API sends numbers as 9-decimal strings; the column holds 5 decimals
    return {
        'cve_id': item['cve'],
        'score_date': datetime.date.fromisoformat(item['date']),
        'epss': round(float(item['epss']), 5),
        'percentile': round(float(item['percentile']), 5),
    }


_EPSS_COLUMNS = ('cve_id', 'score_date', 'epss', 'percentile')


def save_epss(rows: list[dict]) -> int:
    """Upsert parsed EPSS rows into ``epss_scores``. Returns the number of rows.

    Keyed by (cve_id, score_date), so each day's poll adds a new row per CVE
    (building a history) and re-polling the same day just overwrites it.
    """
    conn = get_connection()
    cursor = conn.cursor(prepared=True)
    try:
        upsert_query = f"""
            INSERT INTO epss_scores ({', '.join(_EPSS_COLUMNS)})
            VALUES ({', '.join(['%s'] * len(_EPSS_COLUMNS))})
            AS new
            ON DUPLICATE KEY UPDATE
                epss = new.epss
                , percentile = new.percentile
            """
        for row in rows:
            cursor.execute(upsert_query, tuple(row[c] for c in _EPSS_COLUMNS))
        conn.commit()
    finally:
        cursor.close()
        conn.close()
    return len(rows)
