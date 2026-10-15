// The page only ever calls the local MAVIS API, never Gemini or another external service.
import type { Digest, FeedHealth, FeedItem, WatchlistHit } from './types'

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
export const fetchHealth = () => getJson<FeedHealth[]>('/api/health')
