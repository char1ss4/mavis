"""Local HTTP API for the MAVIS HUD (FastAPI). Binds to 127.0.0.1 only; see `cli.py serve`.

The browser talks only to this API, never to Gemini. Watchlist matches and scores
are served to the local page but, as everywhere else, never sent to an external service.
"""

import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from mavis.briefing.digest import CveBrief, latest_digest
from mavis.scoring.inputs import fetch_scoring_inputs
from mavis.scoring.ranking import rank_cves
from mavis.scoring.watchlist import load_watchlist

WATCHLIST_PATH = 'watchlist.yaml'
FRONTEND_DIST = Path(__file__).resolve().parent.parent / 'frontend' / 'dist'


class WatchlistHit(BaseModel):
    cve_id: str
    severity: Literal['critical', 'high', 'medium', 'low'] | None   # None = NVD hasn't scored it yet
    cvss: float | None
    epss: float | None
    epss_percentile: float | None
    in_kev: bool
    matched_product: str
    match_type: Literal['cpe', 'keyword']
    mavis_score: float
    published_at: datetime | None
    description: str


class DigestResponse(BaseModel):
    id: int
    generated_at: datetime
    model: str
    summary: str
    items: list[CveBrief]
    sources: list[str]


def to_hit(row: dict[str, Any]) -> WatchlistHit:
    """Shape one ranked row (from rank_cves) into the HUD's WatchlistHit."""
    severity = (row['cvss_severity'] or '').lower()
    return WatchlistHit(
        cve_id=row['cve_id'],
        severity=severity if severity in ('critical', 'high', 'medium', 'low') else None,
        cvss=row['cvss_score'],
        epss=row['epss'],
        epss_percentile=row['percentile'],
        in_kev=row['in_kev'],
        matched_product=', '.join(m['name'] for m in row['matches']),
        match_type=row['match_type'],
        mavis_score=round(row['score'], 1),
        published_at=row.get('published'),
        description=' '.join((row['description'] or '').split()),
    )


def compute_hits() -> list[WatchlistHit]:
    """Load, match and rank every stored CVE (several seconds on ~3.4k CVEs)."""
    try:
        watchlist = load_watchlist(WATCHLIST_PATH)
    except FileNotFoundError:
        return []
    ranked = rank_cves(fetch_scoring_inputs(), watchlist)
    return [to_hit(row) for row in ranked if row['matches']]


# Scores only change after a poll or a watchlist edit, so ranking is cached for a few minutes
HITS_CACHE_SECONDS = 300
_hits_cache: tuple[float, list[WatchlistHit]] | None = None
_hits_lock = threading.Lock()


def cached_hits() -> list[WatchlistHit]:
    global _hits_cache
    with _hits_lock:   # concurrent requests wait for one computation instead of each running it
        if _hits_cache is None or time.monotonic() - _hits_cache[0] > HITS_CACHE_SECONDS:
            _hits_cache = (time.monotonic(), compute_hits())
        return _hits_cache[1]


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # Warm the cache in the background so the first page load doesn't wait for ranking
    threading.Thread(target=cached_hits, daemon=True).start()
    yield


app = FastAPI(title='MAVIS', docs_url='/api/docs', openapi_url='/api/openapi.json', lifespan=lifespan)


@app.get('/api/hits', response_model=list[WatchlistHit])
def get_hits(limit: int = 50) -> list[WatchlistHit]:
    """CVEs matching the watchlist, highest MAVIS score first."""
    return cached_hits()[:limit]


@app.get('/api/digest', response_model=DigestResponse)
def get_digest() -> DigestResponse:
    """The newest stored Gemini digest (create one with `python cli.py brief`)."""
    digest = latest_digest()
    if digest is None:
        raise HTTPException(status_code=404, detail='No digest yet. Run: python cli.py brief')
    return DigestResponse(
        id=digest['id'],
        generated_at=digest['created_at'],
        model=digest['model'],
        summary=digest['summary'],
        items=digest['items'],
        sources=['NVD', 'CISA KEV', 'FIRST EPSS'],
    )


# After `npm run build`, serve the built HUD from the same origin so one command runs the demo.
# Mounted last so the /api routes above take priority.
if FRONTEND_DIST.is_dir():
    app.mount('/', StaticFiles(directory=FRONTEND_DIST, html=True), name='frontend')
