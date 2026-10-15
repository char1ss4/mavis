from datetime import datetime

from fastapi.testclient import TestClient

from mavis import api
from mavis.scoring.ranking import rank_cves

WATCHLIST = [{'name': 'chrome', 'vendor': 'google', 'product': 'chrome', 'keywords': ['Google Chrome']}]


def _row(cve_id: str, description: str, severity: str | None = 'HIGH') -> dict:
    return {'cve_id': cve_id, 'published': datetime(2026, 10, 14, 9, 0), 'description': description,
            'cvss_score': 8.1 if severity else None, 'cvss_severity': severity, 'in_kev': False,
            'known_ransomware': None, 'epss': 0.25, 'percentile': 0.8, 'epss_date': None,
            'configurations': []}


def test_to_hit_shapes_a_ranked_row() -> None:
    ranked = rank_cves([_row('CVE-1', 'Use after free in  Google Chrome.', severity=None)], WATCHLIST)

    hit = api.to_hit(ranked[0])

    assert hit.matched_product == 'chrome' and hit.match_type == 'keyword'
    assert hit.severity is None and hit.cvss is None    # unscored stays unscored, not "low"
    assert hit.description == 'Use after free in Google Chrome.'


def test_hits_endpoint_returns_only_matches(monkeypatch) -> None:
    rows = [_row('CVE-1', 'Flaw in Google Chrome.'), _row('CVE-2', 'Flaw in something else.')]
    monkeypatch.setattr(api, 'fetch_scoring_inputs', lambda: rows)
    monkeypatch.setattr(api, 'load_watchlist', lambda path: WATCHLIST)
    monkeypatch.setattr(api, '_hits_cache', None)

    response = TestClient(api.app).get('/api/hits')

    assert response.status_code == 200
    assert [h['cve_id'] for h in response.json()] == ['CVE-1']
    assert response.json()[0]['severity'] == 'high'


def test_digest_endpoint_404_when_none(monkeypatch) -> None:
    monkeypatch.setattr(api, 'latest_digest', lambda: None)

    assert TestClient(api.app).get('/api/digest').status_code == 404
