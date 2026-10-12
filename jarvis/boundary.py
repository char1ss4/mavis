"""Privacy boundary between local data and the external LLM."""


def build_llm_payload(cves: list[dict]) -> list[dict]:
    """Reduce CVE records to the fields allowed to leave the machine.

    Only public CVE fields (e.g. CVE ID, description, CVSS, KEV status, EPSS)
    may be sent to the LLM. The watchlist, match results, and local priority
    scores never leave the machine; this function is the single choke point
    that enforces that.

    Args:
        cves: CVE records, possibly carrying local-only fields.

    Returns:
        Sanitised records containing only allowlisted public fields.
    """
    raise NotImplementedError
