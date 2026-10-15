import cli
from mavis.briefing.boundary import build_llm_payload
from mavis.briefing.digest import Digest, build_prompt, drop_unknown_items, payload_hash

PAYLOAD = build_llm_payload([
    {'cve_id': 'CVE-2026-0002', 'description': 'SQL injection in Foo.', 'cvss_score': 9.8,
     'in_kev': True, 'epss': 0.9, 'score': 88.0, 'matches': [{'name': 'my-secret-app'}]},
    {'cve_id': 'CVE-2026-0001', 'description': 'XSS in Bar.', 'cvss_score': None, 'epss': None},
])


def _item(cve_id: str, urgency: str = 'patch now') -> dict:
    return {'cve_id': cve_id, 'headline': 'Foo SQL injection', 'what_it_is': 'A flaw — bad.',
            'why_it_matters': 'It’s in KEV.', 'action': 'Update Foo.', 'urgency': urgency}


def test_prompt_contains_only_the_payload() -> None:
    prompt = build_prompt(PAYLOAD)

    assert 'CVE-2026-0002' in prompt and 'SQL injection in Foo.' in prompt
    assert 'my-secret-app' not in prompt and '88.0' not in prompt


def test_payload_hash_is_stable_and_content_sensitive() -> None:
    assert payload_hash(PAYLOAD) == payload_hash(build_llm_payload(list(reversed(PAYLOAD))))
    assert payload_hash(PAYLOAD) != payload_hash(PAYLOAD[:1])


def test_drop_unknown_items_removes_made_up_cves() -> None:
    digest = {'summary': 's', 'items': [_item('CVE-2026-0002'), _item('CVE-1999-9999')]}

    assert [i['cve_id'] for i in drop_unknown_items(digest, PAYLOAD)['items']] == ['CVE-2026-0002']


def test_digest_schema_rejects_unknown_urgency() -> None:
    Digest.model_validate({'summary': 's', 'items': [_item('CVE-1')]})
    try:
        Digest.model_validate({'summary': 's', 'items': [_item('CVE-1', urgency='whenever')]})
    except ValueError:
        return
    raise AssertionError('urgency outside the allowed values should fail validation')


def test_format_brief_is_ascii_and_shows_local_context() -> None:
    digest = {'summary': 'Two items. Start with the first — it’s exploited.',
              'items': [_item('CVE-2026-0001', 'monitor'), _item('CVE-2026-0002')]}
    local = {'CVE-2026-0002': {'score': 88.0, 'matches': [{'name': 'foo'}], 'match_type': 'cpe'},
             'CVE-2026-0001': {'score': 20.0, 'matches': [], 'match_type': None}}

    lines = cli.format_brief(digest, local, width=80)
    text = '\n'.join(lines)

    text.encode('ascii')
    assert all(len(line) <= 80 for line in lines)
    assert '[PATCH NOW] CVE-2026-0002  score 88.0 | matches foo (cpe)' in text
    assert '[MONITOR] CVE-2026-0001  score 20.0' in text
    assert "it's exploited" in text
    assert text.index('CVE-2026-0002') < text.index('CVE-2026-0001')   # local score order
