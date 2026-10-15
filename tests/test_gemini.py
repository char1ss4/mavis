from types import SimpleNamespace

import pytest
from google.genai import errors
from pydantic import BaseModel

from mavis import config
from mavis.briefing import gemini


class Reply(BaseModel):
    text: str


def _fake_client(outcomes: dict[str, object], calls: list[str]):
    """A stand-in client: each model either raises the given error or returns a parsed reply."""
    def generate_content(model, contents, config):
        calls.append(model)
        outcome = outcomes[model]
        if isinstance(outcome, Exception):
            raise outcome
        return SimpleNamespace(parsed=outcome)
    return SimpleNamespace(models=SimpleNamespace(generate_content=generate_content))


def _overloaded() -> errors.ServerError:
    return errors.ServerError(503, {'error': {'code': 503, 'message': 'high demand', 'status': 'UNAVAILABLE'}})


def test_falls_back_when_main_model_is_overloaded(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(config, 'GEMINI_FALLBACK_MODELS', ['lite'])
    monkeypatch.setattr(gemini, 'gemini_client', lambda: _fake_client(
        {'main': _overloaded(), 'lite': Reply(text='ok')}, calls))

    parsed, used = gemini.generate_structured('main', 'prompt', 'system', Reply)

    assert (parsed.text, used, calls) == ('ok', 'lite', ['main', 'lite'])


def test_quota_exhausted_moves_to_fallback(monkeypatch) -> None:
    calls: list[str] = []
    quota = errors.ClientError(429, {'error': {'code': 429, 'message': 'quota', 'status': 'RESOURCE_EXHAUSTED'}})
    monkeypatch.setattr(config, 'GEMINI_FALLBACK_MODELS', ['lite'])
    monkeypatch.setattr(gemini, 'gemini_client', lambda: _fake_client({'main': quota, 'lite': Reply(text='ok')}, calls))

    assert gemini.generate_structured('main', 'prompt', 'system', Reply)[1] == 'lite'


def test_raises_last_error_when_every_model_is_overloaded(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(config, 'GEMINI_FALLBACK_MODELS', ['lite'])
    monkeypatch.setattr(gemini, 'gemini_client', lambda: _fake_client(
        {'main': _overloaded(), 'lite': _overloaded()}, calls))

    with pytest.raises(errors.ServerError):
        gemini.generate_structured('main', 'prompt', 'system', Reply)
    assert calls == ['main', 'lite']


def test_other_errors_are_not_retried_on_fallback(monkeypatch) -> None:
    calls: list[str] = []
    bad_request = errors.ClientError(400, {'error': {'code': 400, 'message': 'bad', 'status': 'INVALID_ARGUMENT'}})
    monkeypatch.setattr(config, 'GEMINI_FALLBACK_MODELS', ['lite'])
    monkeypatch.setattr(gemini, 'gemini_client', lambda: _fake_client({'main': bad_request}, calls))

    with pytest.raises(errors.ClientError):
        gemini.generate_structured('main', 'prompt', 'system', Reply)
    assert calls == ['main']


def test_schema_mismatch_raises(monkeypatch) -> None:
    monkeypatch.setattr(config, 'GEMINI_FALLBACK_MODELS', [])
    monkeypatch.setattr(gemini, 'gemini_client', lambda: _fake_client({'main': None}, []))

    with pytest.raises(ValueError):
        gemini.generate_structured('main', 'prompt', 'system', Reply)


def test_models_to_try_skips_duplicates(monkeypatch) -> None:
    monkeypatch.setattr(config, 'GEMINI_FALLBACK_MODELS', ['lite', 'main'])

    assert gemini.models_to_try('main') == ['main', 'lite']
    assert gemini.models_to_try('lite', ['main', 'lite']) == ['lite', 'main']


def test_ask_uses_lite_first_then_main_model(monkeypatch) -> None:
    from mavis.briefing.ask import answer_question

    calls: list[str] = []
    monkeypatch.setattr(config, 'GEMINI_MODEL', 'flash')
    monkeypatch.setattr(config, 'GEMINI_FALLBACK_MODELS', ['lite'])
    reply = SimpleNamespace(text='Patch it.', cited_cve_ids=[])
    monkeypatch.setattr(gemini, 'gemini_client', lambda: _fake_client({'lite': _overloaded(), 'flash': reply}, calls))

    answer = answer_question({'question': 'q', 'cves': []}, 'lite')

    assert calls == ['lite', 'flash'] and answer['model'] == 'flash'
