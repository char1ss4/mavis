from typing import Any

import cli
from mavis.scoring.ranking import rank_cves

CHROME = {'name': 'chrome', 'vendor': 'google', 'product': 'chrome', 'keywords': ['Google Chrome']}
EDGE = {'name': 'edge', 'vendor': 'microsoft', 'product': 'edge_chromium', 'keywords': ['Microsoft Edge']}


def _row(cve_id: str, cvss: float | None = 5.0, epss: float | None = None, in_kev: bool = False,
         description: str = 'Some flaw.', configurations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {'cve_id': cve_id, 'description': description, 'cvss_score': cvss, 'epss': epss,
            'in_kev': in_kev, 'configurations': configurations or []}


def test_rank_cves_sorts_highest_score_first() -> None:
    rows = [_row('CVE-1', cvss=3.0), _row('CVE-2', cvss=9.0, in_kev=True), _row('CVE-3', cvss=6.0)]

    assert [r['cve_id'] for r in rank_cves(rows, [])] == ['CVE-2', 'CVE-3', 'CVE-1']


def test_rank_cves_adds_matches_and_match_type() -> None:
    rows = [_row('CVE-1', description='Use after free in Google Chrome and Microsoft Edge.'), _row('CVE-2')]

    ranked = {r['cve_id']: r for r in rank_cves(rows, [CHROME, EDGE])}

    assert [m['name'] for m in ranked['CVE-1']['matches']] == ['chrome', 'edge']
    assert ranked['CVE-1']['match_type'] == 'keyword'
    # Two matches score the same as one: 17.5 CVSS + 10 keyword
    assert ranked['CVE-1']['score'] == 27.5
    assert ranked['CVE-2']['matches'] == [] and ranked['CVE-2']['match_type'] is None


def test_rank_cves_cpe_match_beats_keyword_match() -> None:
    cpe = [{'nodes': [{'cpeMatch': [{'vulnerable': True,
                                     'criteria': 'cpe:2.3:a:google:chrome:130.0:*:*:*:*:*:*:*'}]}]}]
    rows = [_row('CVE-KW', description='Flaw in Google Chrome.'), _row('CVE-CPE', configurations=cpe)]

    ranked = rank_cves(rows, [CHROME])

    assert [(r['cve_id'], r['match_type']) for r in ranked] == [('CVE-CPE', 'cpe'), ('CVE-KW', 'keyword')]


def test_format_score_table_fits_width_and_shows_missing_cvss_as_dash() -> None:
    ranked = rank_cves([_row('CVE-2026-0001', cvss=None, epss=0.12345, in_kev=True,
                             description='A very long description ' * 20)], [])

    lines = cli.format_score_table(ranked, width=100)

    assert lines[0].startswith('  #  CVE')
    assert all(len(line) <= 100 for line in lines)
    row = lines[1]
    assert ' - ' in row          # CVSS shown as '-', not the neutral 5.0
    assert '12.3%' in row
    assert 'yes' in row
    assert row.endswith('...')
    row.encode('ascii')          # plain ASCII so cp1252 consoles can print it
