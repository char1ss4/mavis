"""Shared Gemini call with structured output, retries and a fallback model.

Only called with payloads built by mavis/briefing/boundary.py.
"""

from typing import Any

from pydantic import BaseModel

from mavis import config

# Gemini returns 503 "high demand" for minutes at a time on popular models. These are
# retried briefly on the same model, then the fallback model is tried.
OVERLOADED_CODES = (500, 503)
# 429 = this model's quota is used up. Retrying only spends more quota, so go straight to
# the fallback model, which has its own separate quota.
FALLBACK_CODES = (429, *OVERLOADED_CODES)


def gemini_client() -> Any:
    """A google-genai client with short retries and a per-request timeout."""
    # Imported here so tests and `--help` don't need the SDK loaded
    from google import genai
    from google.genai import types

    # Two quick retries (2s, 4s); after that it's faster to switch to the fallback model
    return genai.Client(
        api_key=config.GEMINI_API_KEY,
        http_options=types.HttpOptions(
            timeout=30_000,  # ms
            retry_options=types.HttpRetryOptions(
                attempts=3, initial_delay=2.0, exp_base=2.0, http_status_codes=list(OVERLOADED_CODES),
            ),
        ),
    )


def models_to_try(model: str) -> list[str]:
    """The requested model first, then the configured fallbacks (without repeats)."""
    return list(dict.fromkeys([model, *config.GEMINI_FALLBACK_MODELS]))


def generate_structured(model: str, prompt: str, system_instruction: str,
                        schema: type[BaseModel]) -> tuple[BaseModel, str]:
    """Call Gemini with a response schema, moving to a fallback model if one is overloaded.

    Returns:
        The parsed response (an instance of ``schema``) and the model that produced it.

    Raises:
        ValueError: If the response doesn't match the schema.
        google.genai.errors.APIError: If every model failed, or on a non-overload error.
    """
    from google.genai import errors, types

    # Keep a reference: a Client closes its HTTP connection when garbage-collected
    client = gemini_client()
    last_error: Exception | None = None
    for candidate in models_to_try(model):
        try:
            response = client.models.generate_content(
                model=candidate,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    response_mime_type='application/json',
                    response_schema=schema,
                    temperature=0.2,
                ),
            )
        except errors.APIError as exc:
            if exc.code not in FALLBACK_CODES:
                raise
            last_error = exc
            continue
        # The SDK validates the JSON against the schema; parsed is None if that failed
        if response.parsed is None:
            raise ValueError(f"Gemini returned a response that doesn't match the {schema.__name__} schema")
        return response.parsed, candidate
    assert last_error is not None
    raise last_error
