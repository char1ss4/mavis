from edith import scoring


def test_placeholder():
    assert callable(scoring.score_cve)
