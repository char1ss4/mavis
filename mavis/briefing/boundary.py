"""Privacy boundary between local data and the external LLM."""

from decimal import Decimal
from typing import Any

# Public facts about a CVE, all already published by NVD, CISA KEV or FIRST EPSS.
# Anything not listed here (watchlist matches, match type, MAVIS score, raw NVD
# JSON, CPE configurations) is dropped. Add a field only if it is public.
ALLOWED_FIELDS: tuple[str, ...] = (
    'cve_id',
    'description',
    'cvss_score',
    'cvss_severity',
    'in_kev',
    'known_ransomware',
    'epss',
    'percentile',
)


def _public_value(value: Any) -> Any:
    """Make a value JSON-safe: DECIMAL columns arrive as Decimal."""
    return float(value) if isinstance(value, Decimal) else value


def build_llm_payload(cves: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reduce CVE records to the fields allowed to leave the machine.

    Only public CVE fields (e.g. CVE ID, description, CVSS, KEV status, EPSS)
    may be sent to the LLM. The watchlist, match results, and local priority
    scores never leave the machine; this function is the single choke point
    that enforces that.

    The records are also re-sorted by CVE ID, because the order of a ranked
    list would itself reveal the local priority ranking.

    Args:
        cves: CVE records, possibly carrying local-only fields.

    Returns:
        Sanitised records containing only allowlisted public fields.
    """
    # Build new dicts from the allowlist rather than deleting known-private keys,
    # so a local field added later can't leak by default
    payload = [
        {field: _public_value(cve.get(field)) for field in ALLOWED_FIELDS}
        for cve in cves
    ]
    payload.sort(key=lambda record: record['cve_id'])
    return payload


MAX_QUESTION_CHARS = 500


def build_ask_payload(question: str, cves: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the outbound payload for an Ask question: the question plus public CVE context.

    The question is the user's own text, sent as typed (cut to MAX_QUESTION_CHARS).
    MAVIS adds nothing local to it: the CVE context goes through
    :func:`build_llm_payload`, so it carries only allowlisted public fields.

    Args:
        question: What the user typed in the Ask box.
        cves: CVE records chosen as context, possibly carrying local-only fields.

    Returns:
        ``{'question': str, 'cves': [sanitised records]}``.

    Raises:
        ValueError: If the question is empty.
    """
    question = ' '.join(question.split())[:MAX_QUESTION_CHARS]
    if not question:
        raise ValueError('The question is empty')
    return {'question': question, 'cves': build_llm_payload(cves)}
