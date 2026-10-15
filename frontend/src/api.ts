// The page only ever calls the local MAVIS API, never Gemini or another external service.
import type { AskAnswer, Digest, FeedHealth, FeedItem, WatchlistHit } from './types'

export class NotFoundError extends Error {}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path)
  if (response.status === 404) throw new NotFoundError(path)
  if (!response.ok) throw new Error(`${path} returned ${response.status}`)
  return response.json() as Promise<T>
}

export const fetchHits = () => getJson<WatchlistHit[]>('/api/hits')
export const fetchDigest = () => getJson<Digest>('/api/digest')
export const fetchFeed = () => getJson<FeedItem[]>('/api/feed')

/** Ask a question. The backend adds public CVE context and calls Gemini; the page never does. */
export async function postAsk(question: string): Promise<AskAnswer> {
  const response = await fetch('/api/ask', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ question }),
  })
  if (!response.ok) throw new Error(`/api/ask returned ${response.status}`)
  return response.json() as Promise<AskAnswer>
}
export const fetchHealth = () => getJson<FeedHealth[]>('/api/health')
