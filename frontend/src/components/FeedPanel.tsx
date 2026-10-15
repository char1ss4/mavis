import type { FeedHealth, FeedItem } from '../types'
import { feedItemKey, relativeTime } from '../format'
import { Panel } from './Panel'
import { Skeleton } from './Skeleton'
import './FeedPanel.css'

export type FeedState =
  | { status: 'loading' }
  | { status: 'error' }
  /** `fresh` holds keys of items that arrived after the first load (they slide in) */
  | { status: 'ready'; items: FeedItem[]; fresh: Set<string> }

/** "Couldn't reach NVD..." for each feed whose last poll failed (spec section 7). */
function FailedFeedNotes({ health }: { health: FeedHealth[] }) {
  const failed = health.filter(h => h.last_error && h.feed !== 'EPSS')
  return failed.map(h => (
    <p key={h.feed} className="feed__warning">
      Couldn't reach {h.feed} on the last poll.{' '}
      {h.last_success_at ? `Showing data from ${relativeTime(h.last_success_at)}.` : 'No data from it yet.'}
    </p>
  ))
}

/** Spec 5.4: newest NVD and KEV items first; items that arrive after page load slide in. */
export function FeedPanel({ state, health }: { state: FeedState; health: FeedHealth[] }) {
  return (
    <Panel title="Feed" count={state.status === 'ready' ? state.items.length : undefined} className="feed">
      <FailedFeedNotes health={health} />
      {state.status === 'loading' && <Skeleton rows={8} />}
      {state.status === 'error' && <p className="muted">Couldn't load the feed.</p>}
      {state.status === 'ready' && (
        <ol className="feed__list">
          {state.items.map(item => (
            <li key={feedItemKey(item)}
                className={`feed__item ${state.fresh.has(feedItemKey(item)) ? 'feed__item--new' : ''}`}>
              <span className={`feed__source feed__source--${item.source.toLowerCase()} data`}>{item.source}</span>
              <span className="feed__body">
                <a className="feed__title" href={item.url ?? undefined} target="_blank" rel="noreferrer"
                   title={item.title}>
                  <span className="data feed__cve">{item.cve_id}</span> {item.title}
                </a>
                <span className="feed__meta data muted">
                  {item.watchlist_match && <span className="feed__match">● watchlist</span>}
                  {relativeTime(item.at)}
                </span>
              </span>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  )
}
