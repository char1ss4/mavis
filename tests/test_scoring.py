import pytest

from mavis.scoring import scoring


def test_score_breakdown() -> None:
    # 9.8 CVSS -> 34.3, EPSS 0.81 -> sqrt 0.9 * 25 = 22.5, KEV 20, CPE match 20
    assert scoring.score_cve(9.8, 0.81, True, 'cpe') == 96.8


def test_missing_cvss_is_neutral_not_zero() -> None:
    unscored = scoring.score_cve(None, None, False, None)

    assert unscored == 17.5
    assert unscored > scoring.score_cve(0.0, None, False, None)
    assert unscored < scoring.score_cve(9.0, None, False, None)


def test_missing_epss_counts_as_zero() -> None:
    assert scoring.score_cve(5.0, None, False, None) == scoring.score_cve(5.0, 0.0, False, None)


def test_epss_square_root_lifts_small_scores() -> None:
    # 0.01 linear would add 0.25 points; sqrt adds 2.5
    assert scoring.score_cve(0.0, 0.01, False, None) == 2.5


def test_keyword_match_gets_half_the_cpe_boost() -> None:
    base = scoring.score_cve(6.5, 0.01, False, None)

    assert scoring.score_cve(6.5, 0.01, False, 'cpe') == pytest.approx(base + 20)
    assert scoring.score_cve(6.5, 0.01, False, 'keyword') == pytest.approx(base + 10)


def test_kev_adds_flat_bonus() -> None:
    assert scoring.score_cve(7.0, 0.1, True, None) == pytest.approx(scoring.score_cve(7.0, 0.1, False, None) + 20)


def test_maximum_is_100() -> None:
    assert scoring.score_cve(10.0, 1.0, True, 'cpe') == 100.0


def test_unknown_match_type_is_rejected() -> None:
    with pytest.raises(KeyError):
        scoring.score_cve(5.0, None, False, 'maybe')
