// Small display helpers shared by the panels.
import type { FeedHealth, FeedItem } from './types'

/** A CVE can be in the feed twice (published, then added to KEV), so the source is part of the key. */
export const feedItemKey = (item: FeedItem) => `${item.source}:${item.cve_id}`

/** "3h ago", "2d ago" from an ISO timestamp. */
export function relativeTime(iso: string | null, now: number = Date.now()): string {
  if (!iso) return 'unknown'
  const seconds = Math.max(0, (now - new Date(iso).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  if (seconds < 30 * 86400) return `${Math.floor(seconds / 86400)}d ago`
  // "4095d ago" is unreadable; older items get a date
  return new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
}

const DAY_MS = 86_400_000

export type FeedStatus = 'healthy' | 'stale' | 'failed' | 'unknown'

/** Spec 5.6: failed if the last fetch failed, stale if the last success is over 24h old. */
export function feedStatus(health: FeedHealth | undefined, now: number = Date.now()): FeedStatus {
  if (!health || !health.last_attempt_at) return 'unknown'
  if (health.last_error) return 'failed'
  if (!health.last_success_at || now - new Date(health.last_success_at).getTime() > DAY_MS) return 'stale'
  return 'healthy'
}

/** EPSS 0.87507 -> "0.88". Probabilities read better as decimals than percents in a dense list. */
export function formatEpss(epss: number | null): string {
  return epss === null ? '-' : epss.toFixed(2)
}
