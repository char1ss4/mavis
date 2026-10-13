import datetime
from typing import Any

import pytest

from mavis.ingest import epss, kev


def test_parse_kev_entry() -> None:
    raw = {
        'cveID': 'CVE-2026-0001',
        'vendorProject': 'Example',
        'product': 'Widget',
        'vulnerabilityName': 'Example Widget RCE',
        'dateAdded': '2026-10-13',
        'dueDate': '2026-11-03',
        'knownRansomwareCampaignUse': 'Known',
        'cwes': ['CWE-78'],
    }

    row = kev.parse_kev_entry(raw)

    assert row == {
        'cve_id': 'CVE-2026-0001',
        'vendor': 'Example',
        'product': 'Widget',
        'date_added': datetime.date(2026, 10, 13),
        'due_date': datetime.date(2026, 11, 3),
        'known_ransomware': 'Known',
    }


def test_fetch_epss_batches_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    batches: list[list[str]] = []

    def fake_get(params: dict[str, Any]) -> dict[str, Any]:
        ids = params['cve'].split(',')
        batches.append(ids)
        # Pretend EPSS has no score for the first ID of each batch
        return {'data': [{'cve': i, 'epss': '0.1', 'percentile': '0.5', 'date': '2026-10-13'}
                         for i in ids[1:]]}

    monkeypatch.setattr(epss, '_get_with_retry', fake_get)

    cve_ids = [f'CVE-2026-{n:04d}' for n in range(epss.BATCH_SIZE * 2 + 5)]
    results = epss.fetch_epss(cve_ids)

    assert [len(b) for b in batches] == [epss.BATCH_SIZE, epss.BATCH_SIZE, 5]
    assert [i for b in batches for i in b] == cve_ids
    assert len(results) == len(cve_ids) - 3


def test_fetch_epss_empty_list_makes_no_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(params: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError('should not call the API')

    monkeypatch.setattr(epss, '_get_with_retry', fail)

    assert epss.fetch_epss([]) == []


def test_parse_epss_rounds_to_column_precision() -> None:
    row = epss.parse_epss(
        {'cve': 'CVE-2024-3094', 'epss': '0.904610000', 'percentile': '0.998016000', 'date': '2026-10-13'}
    )

    assert row == {
        'cve_id': 'CVE-2024-3094',
        'score_date': datetime.date(2026, 10, 13),
        'epss': 0.90461,
        'percentile': 0.99802,
    }
