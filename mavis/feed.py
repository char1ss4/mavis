"""Recent activity across the stored feeds, for the HUD's feed panel. Local only."""

from datetime import date, datetime, time
from typing import Any

from mavis.db import get_connection

NVD_URL = 'https://nvd.nist.gov/vuln/detail/{}'

_RECENT_CVES = """
    SELECT cve_id, published, description
    FROM cves
    WHERE published IS NOT NULL
    ORDER BY published DESC, cve_id DESC
    LIMIT %s
    """
_RECENT_KEV = """
    SELECT cve_id, vendor, product, date_added
    FROM kev_entries
    WHERE date_added IS NOT NULL
    ORDER BY date_added DESC, cve_id DESC
    LIMIT %s
    """


def _as_datetime(value: date | datetime) -> datetime:
    # KEV only records the day a CVE was added
    return value if isinstance(value, datetime) else datetime.combine(value, time.min)


def recent_items(watchlist_ids: set[str], limit: int = 50) -> list[dict[str, Any]]:
    """Newest NVD CVEs and KEV additions merged into one list, newest first.

    Args:
        watchlist_ids: CVE IDs that match the watchlist, to flag matching items.
        limit: Maximum number of items returned.
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(_RECENT_CVES, (limit,))
        cves = cursor.fetchall()
        cursor.execute(_RECENT_KEV, (limit,))
        kev = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()
    return merge_items(cves, kev, watchlist_ids, limit)


KEV_SHARE = 0.3


def merge_items(cves: list[dict[str, Any]], kev: list[dict[str, Any]],
                watchlist_ids: set[str], limit: int) -> list[dict[str, Any]]:
    """Turn CVE and KEV rows (each newest first) into feed items and merge them, newest first.

    NVD publishes hundreds of CVEs a day, which would push KEV additions (rarer and
    more important) out of the list, so up to KEV_SHARE of the slots go to KEV.
    """
    kev_slots = min(len(kev), round(limit * KEV_SHARE))
    cves, kev = cves[:limit - kev_slots], kev[:kev_slots]
    items = [{
        'source': 'NVD',
        'cve_id': row['cve_id'],
        'title': ' '.join((row['description'] or 'No description yet.').split()),
        'url': NVD_URL.format(row['cve_id']),
        'at': row['published'],
        'watchlist_match': row['cve_id'] in watchlist_ids,
    } for row in cves] + [{
        'source': 'KEV',
        'cve_id': row['cve_id'],
        'title': f"Added to KEV: {row['vendor']} {row['product']}",
        'url': NVD_URL.format(row['cve_id']),
        'at': _as_datetime(row['date_added']),
        'watchlist_match': row['cve_id'] in watchlist_ids,
    } for row in kev]
    items.sort(key=lambda item: item['at'], reverse=True)
    return items
