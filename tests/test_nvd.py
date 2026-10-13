import datetime
from collections.abc import Callable
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


def test_fetch_recent_kev_cves_filters_by_kev_date(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []

    def fake_get(params: dict[str, Any]) -> dict[str, Any]:
        seen.append(params)
        return {'vulnerabilities': [{'cve': {'id': 'CVE-2015-3306'}}], 'totalResults': 1}

    monkeypatch.setattr(nvd, '_get_with_retry', fake_get)
    monkeypatch.setattr(nvd.time, 'sleep', _no_sleep)

    records = nvd.fetch_recent_kev_cves(days=30)

    assert len(seen) == 1
    assert {'kevStartDate', 'kevEndDate'} <= seen[0].keys()
    assert 'pubStartDate' not in seen[0]
    assert records == [{'id': 'CVE-2015-3306'}]


def _record_fetch(
        monkeypatch: pytest.MonkeyPatch, fetch: Callable[[int], list[dict[str, Any]]],
        days: int, pages_per_chunk: list[int]) -> list[tuple[str, int | None]]:
    """Run ``fetch`` against a fake NVD and return the ordered log of requests and sleeps.

    Chunk ``i`` has ``pages_per_chunk[i]`` pages of up to 2 records; its last page is
    partial, so the remaining result set shrinks until pagination stops on its own.
    """
    events: list[tuple[str, int | None]] = []
    chunk_starts: list[str | None] = []

    def fake_get(params: dict[str, Any]) -> dict[str, Any]:
        start = params.get('pubStartDate') or params.get('kevStartDate')
        if start not in chunk_starts:
            chunk_starts.append(start)
        chunk = len(chunk_starts) - 1
        events.append(('request', chunk))

        total = 2 * pages_per_chunk[chunk] - 1
        remaining = total - params['startIndex']
        page = [{'cve': {'id': f'CVE-{chunk}-{i}'}} for i in range(min(2, remaining))]
        return {'vulnerabilities': page, 'totalResults': total}

    def fake_sleep(seconds: float) -> None:
        assert seconds == 0.6
        events.append(('sleep', None))

    monkeypatch.setattr(nvd, '_get_with_retry', fake_get)
    monkeypatch.setattr(nvd.time, 'sleep', fake_sleep)

    fetch(days)
    assert len(chunk_starts) == len(pages_per_chunk)
    return events


@pytest.mark.parametrize('fetch', [nvd.fetch_recent_cves, nvd.fetch_recent_kev_cves])
@pytest.mark.parametrize('days, pages_per_chunk, expected_requests, expected_sleeps', [
    (7, [1], 1, 0),            # single page, single chunk
    (7, [4], 4, 3),            # multiple pages, single chunk
    (150, [3, 2], 5, 4),       # 120 + 30 days -> 2 chunks
    (250, [3, 1, 2], 6, 5),    # 120 + 120 + 10 days -> 3 chunks, one single-page
])
def test_sleeps_between_every_pair_of_requests_and_never_after_the_last(
        monkeypatch: pytest.MonkeyPatch, fetch: Callable[[int], list[dict[str, Any]]], days: int,
        pages_per_chunk: list[int], expected_requests: int, expected_sleeps: int) -> None:
    events = _record_fetch(monkeypatch, fetch, days, pages_per_chunk)
    kinds = [kind for kind, _ in events]

    assert kinds.count('request') == expected_requests
    assert kinds.count('sleep') == expected_sleeps == expected_requests - 1

    # At every chunk boundary, a sleep sits between the two chunks' requests
    requests = [(i, chunk) for i, (kind, chunk) in enumerate(events) if kind == 'request']
    for (_, prev_chunk), (i, chunk) in zip(requests, requests[1:]):
        if chunk != prev_chunk:
            assert events[i - 1] == ('sleep', None), f'no sleep before chunk {chunk}'

    # Strictly alternating, starting and ending with a request: no two requests
    # back-to-back and no sleep after the last one
    assert kinds == ['request', 'sleep'] * expected_sleeps + ['request']


def test_parse_cve_without_cvss_stores_null_not_zero() -> None:
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
