from pathlib import Path
from typing import Any

import pytest

from mavis.scoring import watchlist

FLASK = {'name': 'flask', 'vendor': 'palletsprojects', 'product': 'flask', 'version': '3.0'}
APACHE = {'name': 'apache', 'vendor': 'apache', 'product': 'http_server', 'version': '2.4'}
WATCHLIST = [FLASK, APACHE]


def _cpe_config(*criteria: str, vulnerable: bool = True) -> list[dict[str, Any]]:
    """NVD-style configurations with one node listing the given CPE strings."""
    return [{'nodes': [{'cpeMatch': [{'vulnerable': vulnerable, 'criteria': c} for c in criteria]}]}]


def test_load_watchlist(tmp_path: Path) -> None:
    path = tmp_path / 'watchlist.yaml'
    path.write_text(
        'watchlist:\n'
        '  - name: flask\n'
        '    vendor: palletsprojects\n'
        '    product: flask\n'
        '    version: "3.0"\n',
        encoding='utf-8',
    )

    assert watchlist.load_watchlist(str(path)) == [FLASK]


def test_load_watchlist_empty_file(tmp_path: Path) -> None:
    path = tmp_path / 'watchlist.yaml'
    path.write_text('', encoding='utf-8')

    assert watchlist.load_watchlist(str(path)) == []


def test_load_watchlist_rejects_entry_without_product(tmp_path: Path) -> None:
    path = tmp_path / 'watchlist.yaml'
    path.write_text('watchlist:\n  - name: broken\n    vendor: someone\n', encoding='utf-8')

    with pytest.raises(ValueError, match='broken'):
        watchlist.load_watchlist(str(path))


def test_match_cve_by_cpe() -> None:
    cve = {
        'description': 'A flaw in some web framework.',
        'configurations': _cpe_config('cpe:2.3:a:palletsprojects:flask:3.0.0:*:*:*:*:*:*:*'),
    }

    assert watchlist.match_cve(cve, WATCHLIST) == [{**FLASK, 'match_type': 'cpe'}]


def test_match_cve_ignores_non_vulnerable_cpe() -> None:
    # e.g. "only when running on Flask": a platform condition, not the affected product
    cve = {
        'description': 'A flaw in a Flask extension.',
        'configurations': _cpe_config('cpe:2.3:a:palletsprojects:flask:*:*:*:*:*:*:*:*', vulnerable=False),
    }

    assert watchlist.match_cve(cve, WATCHLIST) == []


def test_match_cve_cpe_data_overrides_description() -> None:
    cve = {
        'description': 'A Kubernetes flaw that can be triggered from a Flask app.',
        'configurations': _cpe_config('cpe:2.3:a:kubernetes:kubernetes:1.30.0:*:*:*:*:*:*:*'),
    }

    assert watchlist.match_cve(cve, WATCHLIST) == []


def test_match_cve_keyword_fallback_without_cpe_data() -> None:
    cve = {'description': 'Apache HTTP Server and FLASK both mentioned.', 'configurations': []}

    assert watchlist.match_cve(cve, WATCHLIST) == [
        {**FLASK, 'match_type': 'keyword'},
        {**APACHE, 'match_type': 'keyword'},
    ]


def test_match_cve_keyword_needs_whole_word() -> None:
    cve = {'description': 'Bug in myflaskapp, which stores flasks.', 'configurations': []}

    assert watchlist.match_cve(cve, WATCHLIST) == []


def test_match_cve_keyword_rejects_hyphenated_names() -> None:
    cve = {'description': 'Indico uses Flask-Multipass for authentication.', 'configurations': []}

    assert watchlist.match_cve(cve, WATCHLIST) == []


def test_match_cve_uses_entry_keywords_instead_of_product() -> None:
    mysql = {'name': 'mysql', 'vendor': 'oracle', 'product': 'mysql', 'keywords': ['Oracle MySQL']}
    fork = {'description': 'MariaDB server is a community developed fork of MySQL server.', 'configurations': []}
    oracle = {
        'description': 'Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB).',
        'configurations': [],
    }

    assert watchlist.match_cve(fork, [mysql]) == []
    assert watchlist.match_cve(oracle, [mysql]) == [{**mysql, 'match_type': 'keyword'}]


def test_load_watchlist_rejects_bad_keywords(tmp_path: Path) -> None:
    path = tmp_path / 'watchlist.yaml'
    path.write_text(
        'watchlist:\n  - name: mysql\n    vendor: oracle\n    product: mysql\n    keywords: Oracle MySQL\n',
        encoding='utf-8',
    )

    with pytest.raises(ValueError, match='keywords'):
        watchlist.load_watchlist(str(path))


def test_example_watchlist_loads() -> None:
    entries = watchlist.load_watchlist('watchlist.example.yaml')

    assert {e['name'] for e in entries} == {'flask', 'mysql', 'docker', 'mosquitto'}


def test_match_cve_does_not_modify_watchlist() -> None:
    cve = {'description': 'Flask bug.', 'configurations': []}
    entries = [dict(FLASK)]

    watchlist.match_cve(cve, entries)

    assert entries == [FLASK]
