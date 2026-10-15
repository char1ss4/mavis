// Shapes returned by the FastAPI backend (mavis/api.py). Keep in sync with its Pydantic models.

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type WatchlistHit = {
  cve_id: string
  severity: Severity | null // null = NVD hasn't scored it yet
  cvss: number | null
  epss: number | null // 0-1 probability
  epss_percentile: number | null
  in_kev: boolean
  matched_product: string
  match_type: 'cpe' | 'keyword'
  mavis_score: number
  published_at: string | null // ISO 8601
  description: string
}

export type CveBrief = {
  cve_id: string
  headline: string
  what_it_is: string
  why_it_matters: string
  action: string
  urgency: 'patch now' | 'patch this week' | 'monitor'
}

export type Digest = {
  id: number
  generated_at: string
  model: string
  summary: string
  items: CveBrief[]
  sources: string[]
}
