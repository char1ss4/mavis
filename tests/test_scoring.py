from mavis.scoring import scoring


def test_placeholder():
    assert callable(scoring.score_cve)
