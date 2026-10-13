# MAVIS

*Mostly Accurate Vulnerability Intelligence System*

Personal threat-intelligence assistant: MAVIS pulls CVEs from NVD, CISA KEV and EPSS into MySQL, scores them against your local watchlist, and turns the results into a plain-English patch briefing with Gemini Flash.

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

## Seed database (offline demo)

A pre-loaded dump lets the demo run without NVD being reachable. `db/seed.sql` is gitignored, so regenerate it locally. The dump runs inside the container, which keeps the file UTF-8 (PowerShell 5.1 `>` would write UTF-16) and keeps credentials off the host command line:

```bash
docker exec mavis-mysql sh -c 'MYSQL_PWD="$MYSQL_PASSWORD" mysqldump -u"$MYSQL_USER" --no-tablespaces "$MYSQL_DATABASE" > /tmp/seed.sql'
docker cp mavis-mysql:/tmp/seed.sql db/seed.sql
```

To restore it (overwrites the dumped tables), run `sh db/restore_seed.sh` from the repo root.

Re-dump after KEV/EPSS ingestion is added; the current seed has CVEs only.

## Privacy boundary

Only public CVE fields are sent to the LLM. Your watchlist, match results and local scores never leave the machine. `mavis/briefing/boundary.py` is the single place that builds the outbound payload. `.env` and `watchlist.yaml` are gitignored.
