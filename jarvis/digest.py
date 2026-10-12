"""Patch briefing generation via Gemini Flash (google-genai)."""


def generate_digest(payload: list[dict], model: str) -> dict:
    """Generate a plain-English patch briefing from a sanitised CVE payload.

    Uses the google-genai client with structured output (a response schema)
    so the result can be validated and stored in ``digests.output_json``.

    Args:
        payload: Output of :func:`jarvis.boundary.build_llm_payload`. Never
            pass unsanitised records here.
        model: Gemini Flash model name.

    Returns:
        The parsed structured digest.
    """
    raise NotImplementedError
