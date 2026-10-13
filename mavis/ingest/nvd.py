"""NVD CVE API 2.0 client."""
import datetime
import json
import time
from typing import Any

# config must be imported before any network I/O (loads .env, OS trust store)
from mavis import config
import requests

from mavis.db import get_connection

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000+00:00"
MAX_WINDOW = datetime.timedelta(days=120)
PAGE_SIZE = 2000
MAX_RETRIES = 5

# CVSS versions in order of preference (v3.1 is what most tooling reports)
CVSS_PREFERENCE = ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40', 'cvssMetricV2')


def _get_with_retry(params: dict[str, Any]) -> dict[str, Any]:
    """GET one page from NVD, backing off and retrying on 403/503 throttling."""
    headers = {
        'apiKey': config.NVD_API_KEY,
        'User-Agent': 'MAVIS NVD Client'
    }

    wait = 2
    status_code = None
    for attempt in range(MAX_RETRIES):
        response = requests.get(NVD_URL, params=params, headers=headers, timeout=30)

        # NVD uses 403 and 503 for throttling/overload, so those are worth retrying
        status_code = response.status_code
        if status_code not in (403, 503):
            response.raise_for_status()  # Raise an error for other HTTP errors
            return response.json()

        if attempt < MAX_RETRIES - 1:
            time.sleep(wait)
            wait *= 2  # 2s, 4s, 8s, 16s

    raise RuntimeError(
        f"NVD still returning HTTP {status_code} after {MAX_RETRIES} attempts"
    )


def fetch_recent_cves(days: int) -> list[dict[str, Any]]:
    """Fetch CVEs published in the last ``days`` days from the NVD CVE API 2.0.

    Implementation notes:
    - Send the key as an ``apiKey`` request header (not a query param).
    - Sleep 0.6s between paginated requests to stay under the keyed rate limit.
    - Back off and retry on HTTP 403 and 503 (NVD uses both for throttling/overload).
    - pubStartDate/pubEndDate may span at most 120 days; split larger ranges.

    Args:
        days: Size of the lookback window in days.

    Returns:
        Raw CVE records (the ``vulnerabilities[].cve`` objects) as dicts.
    """
    # Calculate the start and end dates for the query
    end_date = datetime.datetime.now(datetime.timezone.utc)
    start_date = end_date - datetime.timedelta(days=days)

    cve_records: list[dict[str, Any]] = []

    # Split the date range into chunks of at most 120 days
    current_start_date = start_date
    while current_start_date < end_date:
        current_end_date = min(current_start_date + MAX_WINDOW, end_date)

        # Page through this chunk until we have totalResults records
        start_index = 0
        while True:
            data = _get_with_retry({
                'pubStartDate': current_start_date.strftime(DATE_FORMAT),
                'pubEndDate': current_end_date.strftime(DATE_FORMAT),
                'resultsPerPage': PAGE_SIZE,
                'startIndex': start_index,
            })

            page = data.get('vulnerabilities', [])
            cve_records.extend(item['cve'] for item in page)
            start_index += len(page)

            time.sleep(0.6)  # Stay under the keyed rate limit

            # Stop on an empty page too, so a bad totalResults can't loop forever
            if not page or start_index >= data['totalResults']:
                break

        # Chunks share a boundary; duplicates are absorbed by the upsert
        current_start_date = current_end_date

    return cve_records


def _pick_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """Return (score, severity, source) for the preferred CVSS metric, or all None."""
    for version in CVSS_PREFERENCE:
        entries = metrics.get(version, [])
        if not entries:
            continue

        # Prefer NVD's own score (Primary) over a CNA's (Secondary)
        entry = next((e for e in entries if e.get('type') == 'Primary'), entries[0])
        data = entry['cvssData']

        # v2 keeps baseSeverity next to cvssData rather than inside it
        severity = data.get('baseSeverity') or entry.get('baseSeverity')
        source = entry.get('source')
        return data.get('baseScore'), severity, source[:50] if source else None

    # No CVSS yet: store NULL, never 0 (scoring treats missing as mid-range)
    return None, None, None


def parse_cve(cve: dict[str, Any]) -> dict[str, Any]:
    """Flatten one raw NVD CVE record into a row for the ``cves`` table."""
    description = next(
        (d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'),
        None,
    )
    score, severity, source = _pick_cvss(cve.get('metrics', {}))

    return {
        'cve_id': cve['id'],
        'published': datetime.datetime.fromisoformat(cve['published']),
        'last_modified': datetime.datetime.fromisoformat(cve['lastModified']),
        'description': description,
        'cvss_score': score,
        'cvss_severity': severity,
        'cvss_source': source,
        'raw_json': json.dumps(cve),
    }


_CVE_COLUMNS = (
    'cve_id', 'description', 'published', 'last_modified',
    'cvss_score', 'cvss_severity', 'cvss_source', 'raw_json',
)


def save_cves(rows: list[dict[str, Any]]) -> int:
    """Upsert parsed CVE rows into the ``cves`` table. Returns the number of rows.

    Uses a server-side prepared statement: values travel separately from the
    SQL, so quotes, backslashes and ``;`` in descriptions or raw JSON can't
    corrupt it. (The connector's default ``executemany`` splices every value
    into one big SQL string, which broke on a 7-day poll.)
    """
    conn = get_connection()
    cursor = conn.cursor(prepared=True)
    try:
        upsert_query = f"""
            INSERT INTO cves ({', '.join(_CVE_COLUMNS)})
            VALUES ({', '.join(['%s'] * len(_CVE_COLUMNS))})
            AS new
            ON DUPLICATE KEY UPDATE
                description = new.description
                , published = new.published
                , last_modified = new.last_modified
                , cvss_score = new.cvss_score
                , cvss_severity = new.cvss_severity
                , cvss_source = new.cvss_source
                , raw_json = new.raw_json
            """
        for row in rows:
            cursor.execute(upsert_query, tuple(row[c] for c in _CVE_COLUMNS))
        conn.commit()
    finally:
        cursor.close()
        conn.close()
    return len(rows)


def stored_cve_ids() -> list[str]:
    """Return every CVE ID in the ``cves`` table (used to look up EPSS scores)."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT cve_id FROM cves ORDER BY cve_id")
        return [str(cve_id) for (cve_id,) in cursor.fetchall()]
    finally:
        cursor.close()
        conn.close()