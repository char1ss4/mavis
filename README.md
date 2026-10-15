# MAVIS

*Mostly Accurate Vulnerability Intelligence System*

Personal threat-intelligence assistant: MAVIS pulls CVEs from NVD, CISA KEV and EPSS into MySQL, scores them against your local watchlist, and turns the results into a plain-English patch briefing with Gemini Flash.

## Setup

```bash
cp .env.example .env                       # fill in API keys and MySQL credentials
docker compose up -d                       # MySQL 8; schema loads on first start
python -m venv .venv
source .venv/bin/activate                  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest
```

Then create `watchlist.yaml` (gitignored) listing the software you run; see below.

## Watchlist

```yaml
watchlist:
  - name: chrome                # your own label, shown in the output
    vendor: google              # NVD CPE vendor (nvd.nist.gov -> Search -> CPE)
    product: chrome             # NVD CPE product; "*" matches any product from the vendor
    keywords: ["Google Chrome"] # optional: phrases to search descriptions for
```

CVEs that NVD has analysed are matched on CPE vendor/product. Most recent ones have no CPE data yet, so those are matched by searching the description for `keywords` (default: the product name, or the vendor name for `"*"`). Descriptions often mention a product only as context ("a fork of MySQL"), so specific phrases cut false matches. `version` may be included but isn't used for matching yet.

`db/schema.sql` only runs when the MySQL volume is empty. To reapply it, run `docker compose down -v` (this deletes all stored data).

## Seed database (offline demo)

A pre-loaded dump lets the demo run without NVD being reachable. `db/seed.sql` is gitignored, so regenerate it locally. The dump runs inside the container, which keeps the file UTF-8 (PowerShell 5.1 `>` would write UTF-16) and keeps credentials off the host command line:

```bash
docker exec mavis-mysql sh -c 'MYSQL_PWD="$MYSQL_PASSWORD" mysqldump -u"$MYSQL_USER" --no-tablespaces "$MYSQL_DATABASE" > /tmp/seed.sql'
docker cp mavis-mysql:/tmp/seed.sql db/seed.sql
```

To restore it (overwrites the dumped tables), run `sh db/restore_seed.sh` from the repo root.

The seed covers all ingested tables (`cves`, `kev_entries`, `epss_scores`). Re-dump after schema changes or when you want fresher data.

## Privacy boundary

Only public CVE fields are sent to the LLM. Your watchlist, match results and local scores never leave the machine. `mavis/briefing/boundary.py` is the single place that builds the outbound payload. `.env` and `watchlist.yaml` are gitignored.
