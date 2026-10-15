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

## Patch briefing

```bash
python cli.py brief                 # brief the top 5 scored CVEs
python cli.py brief --matched       # only CVEs on your watchlist
python cli.py brief --dry-run       # print exactly what would be sent, send nothing
```

`brief` sends the top-scored CVEs to Gemini (`GEMINI_MODEL`, default `gemini-flash-latest`) and asks for structured JSON (a summary plus one item per CVE with an urgency of `patch now`, `patch this week` or `monitor`). Each digest is stored in the `digests` table. Running `brief` again on the same CVEs reuses the stored digest instead of calling Gemini, so a demo still works if the API is down; `--fresh` forces a new one.

## HUD (browser frontend)

React + Vite in `frontend/`, served by a FastAPI app (`mavis/api.py`) that binds to `127.0.0.1` only. The page calls only this local API, never Gemini.

```bash
npm install --prefix frontend       # once
npm run build --prefix frontend     # build the HUD into frontend/dist
python cli.py serve                 # API + built HUD on http://127.0.0.1:8000 (API docs at /api/docs)
```

For frontend development, run `python cli.py serve` and `npm run dev --prefix frontend` together; Vite (http://127.0.0.1:5173) reloads on save and forwards `/api` to the backend.

The page refreshes its data every minute. The status strip shows one dot per feed (NVD, KEV, EPSS): healthy, stale (last success over 24h ago) or failed, based on what `poll` recorded in the `feed_runs` table; `poll` now carries on with the other feeds if one fails. The feed panel lists the newest NVD CVEs and KEV additions (up to 30% of the slots are kept for KEV, so the daily flood of NVD CVEs doesn't push them out). The Core in the centre shows the number of critical watchlist hits and has four states: `idle`, `thinking` (loading), `alert` (a new critical hit arrived) and `offline` (the API is unreachable). Add `?core=alert` (or another state) to the URL to preview a state, e.g. for recording.

The Ask box (under the digest) sends your question to Gemini through the backend, together with the public fields of up to 8 stored CVEs picked locally: CVE IDs named in the question first, then descriptions containing the question's words, with ties broken by KEV, EPSS and CVSS (never by watchlist matches or local scores). "Ask MAVIS about this" on a watchlist hit pre-fills only the CVE ID. The question itself is sent as typed, so naming your own products in it is your choice.

If the main Gemini model is overloaded (503) or out of quota (429), MAVIS switches to `GEMINI_FALLBACK_MODELS` (default `gemini-flash-lite-latest`) and shows which model answered.

"Brief me" reads the digest summary aloud with the browser's Web Speech API. Edge's "Natural" voices sound best; they are online voices, so only Gemini's summary is ever spoken (never watchlist matches or scores). The design spec is `.claude/MAVIS_DESIGN.md`.

## Privacy boundary

Only public CVE fields are sent to the LLM: CVE ID, description, CVSS score and severity, KEV status and ransomware note, and EPSS score and percentile. Your watchlist, match results and local scores never leave the machine. `mavis/briefing/boundary.py` is the single place that builds the outbound payload. It copies fields from an allowlist (so a new local field can't leak by default) and re-sorts the records by CVE ID so their order doesn't reveal the local ranking. `.env` and `watchlist.yaml` are gitignored.

Known limitation: *which* CVEs are sent (your top N) can hint at what you run. Padding the selection with unrelated CVEs would hide that; it isn't done yet.
