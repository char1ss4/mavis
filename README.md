# JARVIS/EDITH

Personal threat-intelligence assistant: EDITH pulls CVEs from NVD, CISA KEV and EPSS into MySQL and scores them against your local watchlist; JARVIS turns the results into a plain-English patch briefing with Gemini Flash.

## Setup

```bash
cp .env.example .env                       # fill in API keys and MySQL credentials
cp watchlist.example.yaml watchlist.yaml   # list the software you run
docker compose up -d                       # MySQL 8; schema loads on first start
python -m venv .venv
source .venv/bin/activate                  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest
```

`db/schema.sql` only runs when the MySQL volume is empty. To reapply it, run `docker compose down -v` (this deletes all stored data).

## Privacy boundary

Only public CVE fields are sent to the LLM. Your watchlist, match results and local scores never leave the machine. `jarvis/boundary.py` is the single place that builds the outbound payload. `.env` and `watchlist.yaml` are gitignored.
