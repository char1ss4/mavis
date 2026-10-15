import type { FeedHealth, FeedName } from '../types'
import { feedStatus, relativeTime, type FeedStatus } from '../format'
import './StatusStrip.css'

const FEEDS: FeedName[] = ['NVD', 'KEV', 'EPSS']

const STATUS_TEXT: Record<FeedStatus, string> = {
  healthy: 'healthy',
  stale: 'stale (over 24h old)',
  failed: 'last fetch failed',
  unknown: 'not polled yet',
}

function describe(feed: FeedName, health: FeedHealth | undefined, status: FeedStatus): string {
  if (!health?.last_attempt_at) return `${feed}: ${STATUS_TEXT[status]}`
  const success = health.last_success_at
    ? `last successful fetch ${relativeTime(health.last_success_at)}`
    : 'no successful fetch yet'
  return `${feed}: ${STATUS_TEXT[status]}, ${success}`
}

/** Spec 5.6: wordmark left; one dot per feed and the last sync time on the right. */
export function StatusStrip({ health }: { health: FeedHealth[] | null }) {
  const byFeed = new Map((health ?? []).map(h => [h.feed, h]))
  const lastSync = (health ?? [])
    .map(h => h.last_success_at)
    .filter((t): t is string => t !== null)
    .sort()
    .at(-1) ?? null

  return (
    <header className="status">
      <h1 className="status__wordmark">MAVIS</h1>
      {health && (
        <div className="status__right">
          <ul className="status__feeds" aria-label="Feed health">
            {FEEDS.map(feed => {
              const status = feedStatus(byFeed.get(feed))
              const text = describe(feed, byFeed.get(feed), status)
              return (
                <li key={feed} className="status__feed" tabIndex={0} aria-label={text}>
                  <span className={`status__dot status__dot--${status}`} aria-hidden="true" />
                  <span className="data" aria-hidden="true">{feed}</span>
                  <span className="status__tip data" role="tooltip" aria-hidden="true">{text}</span>
                </li>
              )
            })}
          </ul>
          <span className="data muted">last sync {lastSync ? relativeTime(lastSync) : 'never'}</span>
        </div>
      )}
    </header>
  )
}
