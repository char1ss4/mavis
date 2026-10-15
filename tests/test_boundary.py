import json
from decimal import Decimal
from typing import Any

from mavis.briefing.boundary import ALLOWED_FIELDS, build_llm_payload
from mavis.scoring.ranking import rank_cves

WATCHLIST = [{'name': 'my-secret-app', 'vendor': 'acme', 'product': 'secret_app',
              'keywords': ['Acme Secret App']}]


def _row(cve_id: str, **extra: Any) -> dict[str, Any]:
    return {'cve_id': cve_id, 'description': 'Flaw in Acme Secret App.', 'cvss_score': 9.8,
            'cvss_severity': 'CRITICAL', 'in_kev': True, 'known_ransomware': 'Known',
            'epss': 0.5, 'percentile': 0.9, 'epss_date': '2026-10-14', 'configurations': [], **extra}


def test_payload_keeps_only_allowlisted_fields() -> None:
    ranked = rank_cves([_row('CVE-1')], WATCHLIST)
    assert ranked[0]['matches'] and ranked[0]['score'] > 0   # local fields are really there

    payload = build_llm_payload(ranked)

    assert list(payload[0]) == list(ALLOWED_FIELDS)
    for local_field in ('matches', 'match_type', 'score', 'configurations', 'epss_date'):
        assert local_field not in payload[0]


def test_payload_never_contains_watchlist_names() -> None:
    payload = build_llm_payload(rank_cves([_row('CVE-1'), _row('CVE-2')], WATCHLIST))

    assert 'my-secret-app' not in json.dumps(payload)


def test_unknown_fields_are_dropped_by_default() -> None:
    payload = build_llm_payload([_row('CVE-1', some_future_local_field='private')])

    assert 'some_future_local_field' not in payload[0]


def test_payload_is_sorted_by_cve_id_to_hide_ranking() -> None:
    ranked = [_row('CVE-3'), _row('CVE-1'), _row('CVE-2')]

    assert [r['cve_id'] for r in build_llm_payload(ranked)] == ['CVE-1', 'CVE-2', 'CVE-3']


def test_payload_is_json_safe_and_input_untouched() -> None:
    row = _row('CVE-1', cvss_score=Decimal('7.5'), epss=Decimal('0.12345'))

    payload = build_llm_payload([row])

    assert payload[0]['cvss_score'] == 7.5 and isinstance(payload[0]['epss'], float)
    json.dumps(payload)
    assert 'configurations' in row   # the caller's record is not modified


def test_missing_public_fields_become_none() -> None:
    payload = build_llm_payload([{'cve_id': 'CVE-1', 'description': 'x'}])

    assert payload[0]['cvss_score'] is None and payload[0]['epss'] is None
