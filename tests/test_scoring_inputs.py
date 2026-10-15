import datetime
from decimal import Decimal
from typing import Any

from mavis.scoring import inputs


def _raw_row(**overrides: Any) -> dict[str, Any]:
    """A query row shaped like mysql-connector returns it."""
    row: dict[str, Any] = {
        'cve_id': 'CVE-2015-3306',
        'description': 'ProFTPD mod_copy allows remote file copy.',
        'cvss_score': Decimal('10.0'),
        'cvss_severity': 'CRITICAL',
        'in_kev': 1,
        'known_ransomware': 'Unknown',
        'epss': Decimal('0.99512'),
        'percentile': Decimal('0.99987'),
        'epss_date': datetime.date(2026, 10, 13),
        'configurations': '[{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*"}]}]}]',
    }
    row.update(overrides)
    return row


def test_parse_scoring_row_converts_types() -> None:
    row = inputs.parse_scoring_row(_raw_row())

    assert row['cvss_score'] == 10.0 and type(row['cvss_score']) is float
    assert row['epss'] == 0.99512 and type(row['epss']) is float
    assert row['in_kev'] is True
    assert row['configurations'][0]['nodes'][0]['cpeMatch'][0]['criteria'].startswith('cpe:2.3:a:proftpd')
    # Columns that need no conversion pass through unchanged
    assert row['cve_id'] == 'CVE-2015-3306'
    assert row['epss_date'] == datetime.date(2026, 10, 13)


def test_parse_scoring_row_missing_configurations_is_empty_list() -> None:
    row = inputs.parse_scoring_row(_raw_row(configurations=None))

    assert row['configurations'] == []


def test_parse_scoring_row_keeps_missing_scores_as_none() -> None:
    row = inputs.parse_scoring_row(
        _raw_row(cvss_score=None, epss=None, percentile=None, in_kev=0, known_ransomware=None)
    )

    # None, not 0: score_cve treats a missing CVSS as neutral, not as harmless
    assert row['cvss_score'] is None
    assert row['epss'] is None
    assert row['percentile'] is None
    assert row['in_kev'] is False
