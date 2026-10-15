import argparse
from datetime import date, datetime

import pytest
from fastapi.testclient import TestClient

import cli
from mavis import api, runs
from mavis.feed import merge_items
from mavis.ingest import epss, kev, nvd


def test_merge_items_sorts_newest_first_and_flags_matches() -> None:
    cves = [{'cve_id': 'CVE-A', 'published': datetime(2026, 10, 14, 9), 'description': 'Old  flaw.'},
            {'cve_id': 'CVE-B', 'published': datetime(2026, 10, 15, 8), 'description': None}]
    kev_rows = [{'cve_id': 'CVE-K', 'vendor': 'Acme', 'product': 'Widget', 'date_added': date(2026, 10, 15)}]

    items = merge_items(cves, kev_rows, watchlist_ids={'CVE-A'}, limit=10)

    assert [i['cve_id'] for i in items] == ['CVE-B', 'CVE-K', 'CVE-A']
    assert items[1] == {'source': 'KEV', 'cve_id': 'CVE-K', 'title': 'Added to KEV: Acme Widget',
                        'url': 'https://nvd.nist.gov/vuln/detail/CVE-K', 'at': datetime(2026, 10, 15),
                        'watchlist_match': False}
    assert items[2]['watchlist_match'] and items[2]['title'] == 'Old flaw.'
    assert items[0]['title'] == 'No description yet.'


def test_merge_items_respects_limit() -> None:
    cves = [{'cve_id': f'CVE-{i}', 'published': datetime(2026, 10, i + 1), 'description': 'x'} for i in range(5)]

    assert len(merge_items(cves, [], set(), limit=3)) == 3


def test_merge_items_keeps_room_for_kev_when_nvd_floods() -> None:
    cves = [{'cve_id': f'CVE-N{i}', 'published': datetime(2026, 10, 15, 12), 'description': 'x'} for i in range(50)]
    kev_rows = [{'cve_id': f'CVE-K{i}', 'vendor': 'v', 'product': 'p', 'date_added': date(2026, 10, 10)}
                for i in range(20)]

    items = merge_items(cves, kev_rows, set(), limit=10)

    assert len(items) == 10
    assert [i['source'] for i in items] == ['NVD'] * 7 + ['KEV'] * 3


def test_health_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(api, 'feed_health', lambda: [
        {'feed': 'NVD', 'last_attempt_at': datetime(2026, 10, 15, 9), 'last_success_at': datetime(2026, 10, 14, 9),
         'last_error': 'HTTPError: 503'},
        {'feed': 'KEV', 'last_attempt_at': None, 'last_success_at': None, 'last_error': None},
    ])

    body = TestClient(api.app).get('/api/health').json()

    assert body[0]['last_error'] == 'HTTPError: 503' and body[1]['last_success_at'] is None


def test_poll_keeps_going_when_one_feed_fails(monkeypatch) -> None:
    recorded = []
    monkeypatch.setattr(runs, 'record_run', lambda feed, ok, items=None, error=None: recorded.append((feed, ok, error)))

    def nvd_down(days):
        raise ConnectionError('NVD unreachable')

    monkeypatch.setattr(nvd, 'fetch_recent_cves', nvd_down)
    monkeypatch.setattr(kev, 'fetch_kev', lambda: [{}])
    monkeypatch.setattr(kev, 'parse_kev_entry', lambda entry: entry)
    monkeypatch.setattr(kev, 'save_kev', lambda rows: 1)
    monkeypatch.setattr(nvd, 'stored_cve_ids', lambda: ['CVE-1'])
    monkeypatch.setattr(epss, 'fetch_epss', lambda ids: [{}])
    monkeypatch.setattr(epss, 'parse_epss', lambda item: item)
    monkeypatch.setattr(epss, 'save_epss', lambda rows: 1)

    with pytest.raises(SystemExit, match='Failed feeds: NVD'):
        cli.cmd_poll(argparse.Namespace(days=1, kev_days=30, timing=False))

    assert recorded == [('NVD', False, 'ConnectionError: NVD unreachable'), ('KEV', True, None), ('EPSS', True, None)]
