import { useEffect, useState } from 'react'
import { fetchDigest, fetchHits, NotFoundError } from './api'
import { DigestPanel, type DigestState } from './components/DigestPanel'
import { HitsPanel, type HitsState } from './components/HitsPanel'
import { Panel } from './components/Panel'
import './App.css'

export default function App() {
  const [hits, setHits] = useState<HitsState>({ status: 'loading' })
  const [digest, setDigest] = useState<DigestState>({ status: 'loading' })

  useEffect(() => {
    fetchHits()
      .then(data => setHits({ status: 'ready', hits: data }))
      .catch(() => setHits({ status: 'error' }))
    fetchDigest()
      .then(data => setDigest({ status: 'ready', digest: data }))
      .catch(err => setDigest({ status: err instanceof NotFoundError ? 'missing' : 'error' }))
  }, [])

  const criticalCount = hits.status === 'ready'
    ? hits.hits.filter(h => h.severity === 'critical').length
    : null

  return (
    <div className="hud">
      <header className="hud__strip">
        <h1 className="hud__wordmark">MAVIS</h1>
      </header>

      <HitsPanel state={hits} />

      {/* Placeholder for the Core ring (build step 3); the metric is real text already */}
      <section className="core" aria-label="Critical watchlist hits">
        <div className="core__metric data" aria-live="polite">{criticalCount ?? '-'}</div>
        <div className="core__label muted">critical on your watchlist</div>
      </section>

      <DigestPanel state={digest} />

      <Panel title="Feed" className="feed">
        <p className="muted">The live feed isn't connected yet.</p>
      </Panel>
    </div>
  )
}
