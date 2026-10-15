import { useState } from 'react'
import type { Severity, WatchlistHit } from '../types'
import { formatEpss, relativeTime } from '../format'
import { Panel } from './Panel'
import { Skeleton } from './Skeleton'
import './HitsPanel.css'

export type HitsState =
  | { status: 'loading' }
  | { status: 'error' }
  | { status: 'ready'; hits: WatchlistHit[] }

const BADGE: Record<Severity, string> = { critical: 'CR', high: 'HI', medium: 'MD', low: 'LO' }

/** Severity is never color alone (spec 8): the two-letter code always goes with it. */
function SeverityBadge({ severity }: { severity: Severity | null }) {
  return (
    <span className={`badge badge--${severity ?? 'none'} data`} title={severity ?? 'not scored yet'}>
      {severity ? BADGE[severity] : '--'}
    </span>
  )
}

function HitRow({ hit, onAskAbout }: { hit: WatchlistHit; onAskAbout: (cveId: string) => void }) {
  const [open, setOpen] = useState(false)
  return (
    <li className={`hit ${hit.severity === 'critical' ? 'hit--critical' : ''}`}>
      <button type="button" className="hit__summary" aria-expanded={open} onClick={() => setOpen(o => !o)}>
        <SeverityBadge severity={hit.severity} />
        <span className="hit__main">
          <span className="hit__line">
            <span className="data hit__id">{hit.cve_id}</span>
            <span className="data muted">EPSS {formatEpss(hit.epss)}</span>
            {hit.in_kev && <span className="data hit__kev">KEV</span>}
          </span>
          <span className="hit__product">{hit.matched_product}</span>
          <span className="data muted">Published {relativeTime(hit.published_at)}</span>
        </span>
      </button>
      {open && (
        <div className="hit__details">
          <p>{hit.description}</p>
          <dl className="data">
            <dt>MAVIS score</dt><dd>{hit.mavis_score.toFixed(1)}</dd>
            <dt>CVSS</dt><dd>{hit.cvss?.toFixed(1) ?? 'not scored yet'}</dd>
            <dt>EPSS percentile</dt>
            <dd>{hit.epss_percentile === null ? '-' : `${(hit.epss_percentile * 100).toFixed(1)}%`}</dd>
            <dt>Matched by</dt><dd>{hit.match_type === 'cpe' ? 'CPE (NVD product data)' : 'keyword in description'}</dd>
          </dl>
          {/* Pre-fills only the public CVE ID, never the matched product from the watchlist */}
          <button type="button" className="hit__ask" onClick={() => onAskAbout(hit.cve_id)}>
            Ask MAVIS about this
          </button>
        </div>
      )}
    </li>
  )
}

/** Spec 5.3: watchlist hits, ranked by the backend's MAVIS score (not recomputed here). */
export function HitsPanel({ state, onAskAbout }: { state: HitsState; onAskAbout: (cveId: string) => void }) {
  return (
    <Panel title="Watchlist hits" count={state.status === 'ready' ? state.hits.length : undefined} className="hits">
      {state.status === 'loading' && <Skeleton rows={6} />}
      {state.status === 'error' && <p className="muted">Couldn't load watchlist hits.</p>}
      {state.status === 'ready' && state.hits.length === 0 && (
        <p className="muted">
          Nothing on your watchlist needs attention. Add products to your watchlist to start tracking them.
        </p>
      )}
      {state.status === 'ready' && state.hits.length > 0 && (
        <ol className="hits__list">
          {state.hits.map(hit => <HitRow key={hit.cve_id} hit={hit} onAskAbout={onAskAbout} />)}
        </ol>
      )}
    </Panel>
  )
}
