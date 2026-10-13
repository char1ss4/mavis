import datetime
from typing import Any

import pytest

from mavis.ingest import nvd


def _no_sleep(seconds: float) -> None:
    pass


def test_fetch_splits_long_ranges_into_120_day_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    windows: list[tuple[datetime.datetime, datetime.datetime]] = []

    def fake_get(params: dict[str, Any]) -> dict[str, Any]:
        windows.append((
            datetime.datetime.strptime(params['pubStartDate'], nvd.DATE_FORMAT),
            datetime.datetime.strptime(params['pubEndDate'], nvd.DATE_FORMAT),
        ))
        return {'vulnerabilities': [], 'totalResults': 0}

    monkeypatch.setattr(nvd, '_get_with_retry', fake_get)
    monkeypatch.setattr(nvd.time, 'sleep', _no_sleep)

    nvd.fetch_recent_cves(days=250)

    # 250 days -> 120 + 120 + 10
    assert len(windows) == 3
    assert all(end - start <= nvd.MAX_WINDOW for start, end in windows)
    # Windows are contiguous and cover the whole range
    for (_, prev_end), (next_start, _) in zip(windows, windows[1:]):
        assert prev_end == next_start
    assert windows[-1][1] - windows[0][0] == datetime.timedelta(days=250)


def test_fetch_pages_until_total_results(monkeypatch: pytest.MonkeyPatch) -> None:
    start_indexes: list[int] = []

    def fake_get(params: dict[str, Any]) -> dict[str, Any]:
        start_indexes.append(params['startIndex'])
        page_size = 2 if params['startIndex'] < 4 else 1
        page = [{'cve': {'id': f"CVE-2026-{params['startIndex'] + i}"}} for i in range(page_size)]
        return {'vulnerabilities': page, 'totalResults': 5}

    monkeypatch.setattr(nvd, '_get_with_retry', fake_get)
    monkeypatch.setattr(nvd.time, 'sleep', _no_sleep)

    records = nvd.fetch_recent_cves(days=7)

    assert start_indexes == [0, 2, 4]
    assert len(records) == 5


def test_fetch_recent_kev_cves_filterdef test_parse_cve_without_cvss_stores_null_not_zero() -> None:
    raw: dict[str, Any] = {
        'id': 'CVE-2026-0001',
        'published': '2026-10-12T10:15:00.000',
        'lastModified': '2026-10-12T11:00:00.000',
        'descriptions': [
            {'lang': 'es', 'value': 'Descripción'},
            {'lang': 'en', 'value': 'A test vulnerability.'},
        ],
        'metrics': {},
    }

    row = nvd.parse_cve(raw)

    assert row['cve_id'] == 'CVE-2026-0001'
    assert row['description'] == 'A test vulnerability.'
    assert row['cvss_score'] is None
    assert row['cvss_severity'] is None
    assert row['cvss_source'] is None


def test_pick_cvss_prefers_v31_and_primary_source() -> None:
    metrics: dict[str, Any] = {
        'cvssMetricV2': [{'type': 'Primary', 'source': 'nvd@nist.gov',
                          'cvssData': {'baseScore': 5.0}, 'baseSeverity': 'MEDIUM'}],
        'cvssMetricV31': [
            {'type': 'Secondary', 'source': 'cna@example.com',
             'cvssData': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL'}},
            {'type': 'Primary', 'source': 'nvd@nist.gov',
             'cvssData': {'baseScore': 7.5, 'baseSeverity': 'HIGH'}},
        ],
    }

    assert nvd._pick_cvss(metrics) == (7.5, 'HIGH', 'nvd@nist.gov')  # pyright: ignore[reportPrivateUsage]
