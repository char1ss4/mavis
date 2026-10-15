# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**MAVIS** (Mostly Accurate Vulnerability Intelligence System): a personal threat-intelligence assistant in a single `mavis` package.

## Project status

Scaffold stage: most functions in `mavis/` and `cli.py` are typed stubs that `raise NotImplementedError`. Their docstrings are the spec (including API quirks and edge cases), so read the docstring before implementing and keep the existing signatures. Python 3.10+ (uses `X | None` syntax).

## Commands

```bash
docker compose up -d                 # MySQL 8 on 127.0.0.1:${MYSQL_PORT:-3306}; needs .env filled in
pip install -r requirements.txt      # into .venv (Windows: .venv\Scripts\activate)
pytest                               # all tests
pytest tests/test_scoring.py::test_placeholder   # single test
python cli.py poll --days 7          # ingest NVD + KEV + EPSS into MySQL
python cli.py score                  # score stored CVEs against watchlist.yaml
python cli.py brief                  # LLM patch briefing for top-scored CVEs
```

`db/schema.sql` is applied only when the MySQL volume is empty (via `docker-entrypoint-initdb.d`). Schema changes require `docker compose down -v`, which deletes all stored data — confirm with the user first.

No linter/formatter is configured.

## Architecture

```
cli.py poll  ──►  mavis/ingest/    NVD + KEV + EPSS  ──►  MySQL
cli.py score ──►  mavis/scoring/   MySQL + watchlist.yaml ──► local scores (stay local)
cli.py brief ──►  mavis/briefing/  boundary.py (allowlist) ──► digest.py ──► Gemini ──► digests table
```

MySQL is the hand-off between stages.

- `mavis/ingest/` — `nvd.py`, `kev.py`, `epss.py`: clients for NVD CVE API 2.0, CISA KEV, FIRST EPSS. NVD rules live in the `fetch_recent_cves` docstring (key in `apiKey` header, 0.6s between pages, retry on 403/503, max 120-day date windows).
- `mavis/scoring/` — local only.
  - `scoring.py`: `score_cve` combines CVSS, EPSS, KEV membership and watchlist match. A missing CVSS score must count as a neutral mid-range value, not zero.
  - `watchlist.py`: loads `watchlist.yaml` (vendor/product/version entries) and matches CVEs against it.
- `mavis/briefing/` — LLM layer using Gemini Flash through `google-genai`.
  - `boundary.py`: `build_llm_payload` is the **only** place that builds outbound LLM data. It allowlists public CVE fields (ID, description, CVSS, KEV status, EPSS).
  - `digest.py`: `generate_digest` takes only the sanitised payload and uses structured output (a response schema); results go to `digests.output_json`.
- `mavis/config.py` loads `.env` via python-dotenv at import time and calls `truststore.inject_into_ssl()` so HTTPS uses the OS certificate store; anything that does network I/O must import it first. `mavis/db.py` opens connections with `mysql-connector-python`.

### Database (`db/schema.sql`)

Tables `cves`, `kev_entries`, `epss_scores` (keyed by `cve_id, score_date`) and `digests`. There are intentionally no foreign keys from KEV/EPSS to `cves`, because those feeds reference CVEs older than the NVD polling window.

## Privacy boundary (hard rule)

The watchlist, match results and local priority scores must never leave the machine. Every LLM payload goes through `mavis/briefing/boundary.py`; never pass raw records to `mavis/briefing/digest.py` or add another path to an external service. **Exception, text-to-speech:** MAVIS may send text to an online voice (a browser's online voices or a cloud text-to-speech API) to speak it, but only text that is already allowed out: Gemini's output, which was generated from the boundary payload. Never send the watchlist, match results, local scores, or locally written text that contains them.

`.env` and `watchlist.yaml` are gitignored. Use `.env.example` as the template for `.env` (the watchlist format is documented in README.md) and don't commit the real files.

**Never open secrets.** Do not read, print, search, `cat`/`type`/`Get-Content`, or otherwise output the contents of `.env` or `watchlist.yaml`, by any tool or command, even to debug. Use `.env.example` and the "Watchlist" section of README.md to learn the formats. To check whether a variable is set, test for presence only (e.g. `bool(os.getenv("NVD_API_KEY"))`) and never echo its value. If a task seems to need the real contents, ask the user instead. `.claude/settings.json` enforces part of this with deny rules, but the rule applies even where those don't reach.
