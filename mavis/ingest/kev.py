"""CISA Known Exploited Vulnerabilities (KEV) catalog client."""
import datetime
from typing import Any

# config must be imported before any network I/O (loads .env, OS trust store)
from mavis import config
import requests

from mavis.db import get_connection

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev() -> list[dict[str, Any]]:
    """Download the full CISA KEV catalog.

    Returns:
        KEV entries (the ``vulnerabilities`` array of the JSON feed) as dicts.
    """
    # One static JSON file (~1.7k entries), no key or paging needed
    response = requests.get(KEV_URL, headers={'User-Agent': 'MAVIS KEV Client'}, timeout=60)
    response.raise_for_status()
    return response.json()['vulnerabilities']


def _parse_date(value: str | None) -> datetime.date | None:
    return datetime.date.fromisoformat(value) if value else None


def parse_kev_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Flatten one raw KEV entry into a row for the ``kev_entries`` table."""
    return {
        'cve_id': entry['cveID'],
        'vendor': entry.get('vendorProject'),
        'product': entry.get('product'),
        'date_added': _parse_date(entry.get('dateAdded')),
        'due_date': _parse_date(entry.get('dueDate')),
        'known_ransomware': entry.get('knownRansomwareCampaignUse'),  # "Known" / "Unknown"
    }


_KEV_COLUMNS = ('cve_id', 'vendor', 'product', 'date_added', 'due_date', 'known_ransomware')


def save_kev(rows: list[dict[str, Any]]) -> int:
    """Upsert parsed KEV rows into ``kev_entries``. Returns the number of rows.

    Same prepared-statement upsert as ``nvd.save_cves``. The whole catalog is
    re-sent every poll, so re-running only refreshes existing rows.
    """
    conn = get_connection()
    cursor = conn.cursor(prepared=True)
    try:
        upsert_query = f"""
            INSERT INTO kev_entries ({', '.join(_KEV_COLUMNS)})
            VALUES ({', '.join(['%s'] * len(_KEV_COLUMNS))})
            AS new
            ON DUPLICATE KEY UPDATE
                vendor = new.vendor
                , product = new.product
                , date_added = new.date_added
                , due_date = new.due_date
                , known_ransomware = new.known_ransomware
            """
        for row in rows:
            cursor.execute(upsert_query, tuple(row[c] for c in _KEV_COLUMNS))
        conn.commit()
    finally:
        cursor.close()
        conn.close()
    return len(rows)
