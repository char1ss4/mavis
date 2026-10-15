import json

import pytest
from fastapi.testclient import TestClient

from mavis import api
from mavis.briefing.ask import answer_sources, build_prompt, find_context
from mavis.briefing.boundary import ALLOWED_FIELDS, build_ask_payload
from mavis.scoring.ranking import rank_cves


def _row(cve_id: str, description: str, in_kev: bool = False, epss: float | None = None,
         cvss: float | None = 5.0) -> dict:
    return {'cve_id': cve_id, 'description': description, 'cvss_score': cvss, 'cvss_severity': 'MEDIUM',
            'in_kev': in_kev, 'known_ransomware': None, 'epss': epss, 'percentile': None,
            'configurations': []}


ROWS = [
    _row('CVE-2026-0001', 'SQL injection in Acme Shop.'),
    _row('CVE-2026-0002', 'Heap overflow in OpenSSL during handshake.', epss=0.4),
    _row('CVE-2026-0003', 'OpenSSL certificate parsing crash.', in_kev=True),
    _row('CVE-2026-0004', 'XSS in a forum plugin.', in_kev=True, epss=0.9),
]


def test_named_cve_ids_come_first() -> None:
    context = find_context('Tell me about cve-2026-0001 and OpenSSL', ROWS)

    assert [r['cve_id'] for r in context] == ['CVE-2026-0001', 'CVE-2026-0003', 'CVE-2026-0002']


def test_keyword_ties_broken_by_public_evidence_not_watchlist() -> None:
    watchlist = [{'name': 'mine', 'vendor': 'x', 'product': 'y', 'keywords': ['handshake']}]
    ranked = rank_cves(ROWS, watchlist)   # CVE-0002 gets a local watchlist boost

    context = find_context('Is OpenSSL being exploited?', ranked)

    # KEV beats the watchlist-boosted CVE: selection never uses local scores
    assert [r['cve_id'] for r in context] == ['CVE-2026-0003', 'CVE-2026-0002']


def test_generic_question_falls_back_to_most_exploited() -> None:
    context = find_context('What should I patch first?', ROWS, limit=2)

    assert [r['cve_id'] for r in context] == ['CVE-2026-0004', 'CVE-2026-0003']


def test_ask_payload_is_question_plus_public_fields_only() -> None:
    watchlist = [{'name': 'my-secret-app', 'vendor': 'x', 'product': 'y', 'keywords': ['Acme Shop']}]
    payload = build_ask_payload('  What about\n Acme Shop? ', rank_cves(ROWS[:1], watchlist))

    assert payload['question'] == 'What about Acme Shop?'
    assert list(payload['cves'][0]) == list(ALLOWED_FIELDS)
    prompt = build_prompt(payload)
    assert 'my-secret-app' not in prompt and 'match' not in prompt


def test_ask_payload_rejects_empty_question() -> None:
    with pytest.raises(ValueError):
        build_ask_payload('   ', [])


def test_ask_payload_caps_question_length() -> None:
    assert len(build_ask_payload('x' * 5000, [])['question']) == 500


def test_answer_sources() -> None:
    assert answer_sources([]) == []
    assert answer_sources([{'in_kev': True, 'epss': None}]) == ['NVD', 'CISA KEV']
    assert answer_sources([{'in_kev': False, 'epss': 0.1}]) == ['NVD', 'FIRST EPSS']


def test_ask_endpoint_sends_only_the_boundary_payload(monkeypatch) -> None:
    sent = {}

    def fake_answer(payload, model):
        sent['payload'] = payload
        return {'text': 'Patch OpenSSL.', 'cited_cve_ids': ['CVE-2026-0003'], 'sources': ['NVD', 'CISA KEV'],
                'model': 'gemini-flash-lite-latest'}

    monkeypatch.setattr(api, 'fetch_scoring_inputs', lambda: rank_cves(ROWS, []))
    monkeypatch.setattr(api, 'answer_question', fake_answer)

    response = TestClient(api.app).post('/api/ask', json={'question': 'OpenSSL?'})

    assert response.status_code == 200 and response.json()['text'] == 'Patch OpenSSL.'
    assert set(sent['payload']) == {'question', 'cves'}
    assert all(list(record) == list(ALLOWED_FIELDS) for record in sent['payload']['cves'])
    assert '"matches"' not in json.dumps(sent['payload'])


def test_ask_endpoint_reports_gemini_failure(monkeypatch) -> None:
    def failing(payload, model):
        raise RuntimeError('503 UNAVAILABLE')

    monkeypatch.setattr(api, 'fetch_scoring_inputs', lambda: ROWS)
    monkeypatch.setattr(api, 'answer_question', failing)

    response = TestClient(api.app).post('/api/ask', json={'question': 'OpenSSL?'})

    assert response.status_code == 502


def test_ask_endpoint_rejects_blank_question(monkeypatch) -> None:
    monkeypatch.setattr(api, 'fetch_scoring_inputs', lambda: ROWS)

    assert TestClient(api.app).post('/api/ask', json={'question': '  '}).status_code == 422
