"""NVD CVE API 2.0 client."""


def fetch_recent_cves(days: int) -> list[dict]:
    """Fetch CVEs published in the last ``days`` days from the NVD CVE API 2.0.

    Implementation notes:
    - Send the key as an ``apiKey`` request header (not a query param).
    - Sleep 0.6s between paginated requests to stay under the keyed rate limit.
    - Back off and retry on HTTP 403 and 503 (NVD uses both for throttling/overload).
    - pubStartDate/pubEndDate may span at most 120 days; split larger ranges.

    Args:
        days: Size of the lookback window in days.

    Returns:
        Raw CVE records (the ``vulnerabilities[].cve`` objects) as dicts.
    """
    raise NotImplementedError
