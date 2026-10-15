import { useEffect, useRef, useState } from 'react'
import { fetchDigest, fetchFeed, fetchHealth, fetchHits, NotFoundError, postAsk } from './api'
import { Core, type CoreState } from './components/Core'
import { DigestPanel, type AskState, type DigestState } from './components/DigestPanel'
import { FeedPanel, type FeedState } from './components/FeedPanel'
import { feedItemKey } from './format'
import { HitsPanel, type HitsState } from './components/HitsPanel'
import { StatusStrip } from './components/StatusStrip'
import type { FeedHealth, WatchlistHit } from './types'
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
  const [question, setQuestion] = useState('')
  const [ask, setAsk] = useState<AskState>({ status: 'idle' })
  const askInput = useRef<HTMLInputElement>(null)
  const [feed, setFeed] = useState<FeedState>({ status: 'loading' })
  const [health, setHealth] = useState<FeedHealth[] | null>(null)
  const knownCriticals = useRef<Set<string> | null>(null) // null until the first load
  const knownFeedKeys = useRef<Set<string> | null>(null)
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

    const loadFeed = () => fetchFeed()
      .then(items => {
        const keys = items.map(feedItemKey)
        // Only items that appear after the first load slide in
        const fresh = knownFeedKeys.current ? new Set(keys.filter(k => !knownFeedKeys.current!.has(k))) : new Set<string>()
        knownFeedKeys.current = new Set([...(knownFeedKeys.current ?? []), ...keys])
        setFeed({ status: 'ready', items, fresh })
      })
      .catch(() => setFeed(prev => (prev.status === 'ready' ? prev : { status: 'error' })))

    const loadHealth = () => fetchHealth().then(setHealth).catch(() => { /* keep the last known health */ })

    const loadAll = () => { loadHits(); loadDigest(); loadFeed(); loadHealth() }
    loadAll()
    const refresh = window.setInterval(loadAll, REFRESH_MS)
    return () => { window.clearInterval(refresh); window.clearTimeout(alertTimer) }
  }, [])

  const askMavis = () => {
    const asked = question.trim()
    setAsk({ status: 'thinking', question: asked })
    postAsk(asked)
      .then(answer => { setAsk({ status: 'answered', question: asked, answer }); setQuestion('') })
      .catch(() => setAsk({ status: 'error', question: asked }))
  }

  /** "Ask MAVIS about this" on a hit: pre-fill the public CVE ID and focus the input. */
  const askAbout = (cveId: string) => {
    setQuestion(`What should I know about ${cveId}?`)
    askInput.current?.focus()
  }

  const criticalCount = hits.status === 'ready' ? criticalIds(hits.hits).size : null

  const coreState: CoreState = forced
    ?? (offline ? 'offline'
      : hits.status === 'loading' || ask.status === 'thinking' ? 'thinking'
      : alerting ? 'alert'
      : 'idle')

  return (
    <div className="hud">
      <StatusStrip health={health} />

      <HitsPanel state={hits} onAskAbout={askAbout} />

      <Core state={coreState} count={criticalCount} alerted={alerted || forced === 'alert'} />

      <DigestPanel state={digest} ask={ask} question={question} onQuestionChange={setQuestion}
                   onAsk={askMavis} onClearAnswer={() => setAsk({ status: 'idle' })} inputRef={askInput} />

      <FeedPanel state={feed} health={health ?? []} />

      <div className="visually-hidden" aria-live="polite">{announcement}</div>
    </div>
  )
}
