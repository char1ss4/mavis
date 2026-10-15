import { useEffect, useRef, useState } from 'react'
import { fetchDigest, fetchHits, NotFoundError } from './api'
import { Core, type CoreState } from './components/Core'
import { DigestPanel, type DigestState } from './components/DigestPanel'
import { HitsPanel, type HitsState } from './components/HitsPanel'
import { Panel } from './components/Panel'
import type { WatchlistHit } from './types'
import './App.css'

const REFRESH_MS = 60_000
const ALERT_MS = 1_200 // long enough for the 600ms pulse, then back to idle colors

const CORE_STATES: CoreState[] = ['idle', 'thinking', 'alert', 'offline']

/** `?core=alert` etc. forces a Core state, for previewing the design and recording the demo. */
function forcedCoreState(): CoreState | null {
  const value = new URLSearchParams(window.location.search).get('core')
  return CORE_STATES.find(s => s === value) ?? null
}

const criticalIds = (hits: WatchlistHit[]) =>
  new Set(hits.filter(h => h.severity === 'critical').map(h => h.cve_id))

export default function App() {
  const [hits, setHits] = useState<HitsState>({ status: 'loading' })
  const [digest, setDigest] = useState<DigestState>({ status: 'loading' })
  const [offline, setOffline] = useState(false)
  const [alerting, setAlerting] = useState(false)
  const [alerted, setAlerted] = useState(false)
  const [announcement, setAnnouncement] = useState('')
  const knownCriticals = useRef<Set<string> | null>(null) // null until the first load
  const [forced] = useState(forcedCoreState) // read the URL once

  useEffect(() => {
    let alertTimer = 0

    const loadHits = () => fetchHits()
      .then(data => {
        setOffline(false)
        setHits({ status: 'ready', hits: data })
        const current = criticalIds(data)
        // Alert only for criticals that appear after the first load, never on page load
        const fresh = knownCriticals.current
          ? data.filter(h => current.has(h.cve_id) && !knownCriticals.current!.has(h.cve_id))
          : []
        knownCriticals.current = current
        if (fresh.length > 0) {
          setAlerting(true)
          setAlerted(true)
          setAnnouncement(`New critical watchlist hit: ${fresh.map(h => h.cve_id).join(', ')}`)
          window.clearTimeout(alertTimer)
          alertTimer = window.setTimeout(() => setAlerting(false), ALERT_MS)
        }
      })
      .catch(() => {
        // Keep showing the last good data; the Core tells the user the backend is unreachable
        setOffline(true)
        setHits(prev => (prev.status === 'ready' ? prev : { status: 'error' }))
      })

    const loadDigest = () => fetchDigest()
      .then(data => setDigest({ status: 'ready', digest: data }))
      .catch(err => setDigest(prev => {
        if (err instanceof NotFoundError) return { status: 'missing' }
        return prev.status === 'ready' ? prev : { status: 'error' }
      }))

    loadHits()
    loadDigest()
    const refresh = window.setInterval(() => { loadHits(); loadDigest() }, REFRESH_MS)
    return () => { window.clearInterval(refresh); window.clearTimeout(alertTimer) }
  }, [])

  const criticalCount = hits.status === 'ready' ? criticalIds(hits.hits).size : null

  const coreState: CoreState = forced
    ?? (offline ? 'offline'
      : hits.status === 'loading' ? 'thinking'
      : alerting ? 'alert'
      : 'idle')

  return (
    <div className="hud">
      <header className="hud__strip">
        <h1 className="hud__wordmark">MAVIS</h1>
      </header>

      <HitsPanel state={hits} />

      <Core state={coreState} count={criticalCount} alerted={alerted || forced === 'alert'} />

      <DigestPanel state={digest} />

      <Panel title="Feed" className="feed">
        <p className="muted">The live feed isn't connected yet.</p>
      </Panel>

      <div className="visually-hidden" aria-live="polite">{announcement}</div>
    </div>
  )
}
