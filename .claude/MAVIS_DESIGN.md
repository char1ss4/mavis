# MAVIS Frontend Design Spec

> Read this file before writing or changing any frontend code in this repo.
> It is the source of truth for MAVIS's look, layout, motion and copy.
> If code and this spec disagree, follow the spec and flag the conflict.

## 1. What MAVIS is

MAVIS ("Mostly Accurate Vulnerability Intelligence System") is a personal cybersecurity
threat-intel assistant. It pulls from NVD, CISA KEV and EPSS (plus news RSS), stores data
in MySQL, scores items against a local watchlist, and uses Gemini to write a short digest.

The frontend is a single-screen heads-up display (HUD) that does two things:

1. **Pushes** what matters: new items that hit the watchlist, newly added KEV entries,
   high EPSS scores.
2. **Answers** when asked: the user types a question and MAVIS replies in the digest panel.

Audience: one user (the owner), plus reviewers watching a 2–4 minute demo video.
The screen must read clearly on a screen recording at 1080p.

## 2. Hard rules

- **Original design only.** The style is the sci-fi "holographic HUD" genre. Do not copy
  screens, logos, reactor/arc shapes, suit graphics, fonts or names from Iron Man / Marvel
  films. Never use the words "JARVIS", "EDITH", "Stark" or "Iron Man" in UI text, code
  identifiers, asset names or comments. The product name is MAVIS.
- **No external image assets.** All decoration is inline SVG and CSS.
- **Hierarchy beats decoration.** A critical, actively exploited CVE on the watchlist must
  be the most visually dominant thing on screen. Rings and ticks are background texture.
- **No sensitive local data in the UI layer** beyond what the backend already exposes.
  The frontend never calls Gemini directly; it calls the MAVIS backend.
- **Respect `prefers-reduced-motion`.** All looping animation stops; boot sequence
  becomes a 200ms fade.
- **Stack:** use whatever frontend stack already exists in the repo. If there is none,
  ask the user before choosing one. Do not add a UI component library.

## 3. Design tokens

Define these as CSS custom properties on `:root`. Do not hard-code colors elsewhere.

```css
:root {
  /* Surfaces */
  --mv-bg:          #04090C; /* deep blue-black, the "void" */
  --mv-panel:       rgba(12, 32, 40, 0.55); /* translucent glass */
  --mv-panel-edge:  rgba(110, 231, 240, 0.28);

  /* Signal colors */
  --mv-primary:     #6EE7F0; /* cool cyan: default lines, text accents */
  --mv-primary-dim: #2A6E78; /* inactive rings, gridlines, tick marks */
  --mv-text:        #D8F6F8; /* body text */
  --mv-text-muted:  #7FA9AE; /* secondary labels, timestamps */

  /* Severity (use ONLY for severity, never decoration) */
  --mv-sev-low:     #6EE7F0; /* same as primary */
  --mv-sev-medium:  #F2C14E; /* amber */
  --mv-sev-high:    #FF8A3D; /* orange */
  --mv-sev-critical:#FF4D5E; /* red */

  /* Glow */
  --mv-glow:        0 0 6px rgba(110, 231, 240, 0.55), 0 0 18px rgba(110, 231, 240, 0.18);
  --mv-glow-crit:   0 0 8px rgba(255, 77, 94, 0.7),   0 0 24px rgba(255, 77, 94, 0.25);

  /* Lines */
  --mv-line-hair:   1px;
  --mv-line-thin:   1.5px;

  /* Type */
  --mv-font-ui:     "Rajdhani", "Barlow Semi Condensed", system-ui, sans-serif;
  --mv-font-data:   "JetBrains Mono", "IBM Plex Mono", ui-monospace, monospace;

  /* Spacing scale (px) */
  --mv-space-1: 4px;  --mv-space-2: 8px;  --mv-space-3: 12px;
  --mv-space-4: 16px; --mv-space-5: 24px; --mv-space-6: 40px;

  /* Motion */
  --mv-ease:        cubic-bezier(0.2, 0.8, 0.2, 1);
  --mv-fast:        150ms;
  --mv-med:         400ms;
}
```

### Typography

| Role | Font | Size | Weight | Notes |
|---|---|---|---|---|
| Wordmark "MAVIS" | `--mv-font-ui` | 28px | 600 | letter-spacing 0.3em |
| Panel titles | `--mv-font-ui` | 14px | 600 | sentence case, letter-spacing 0.08em |
| Body / digest text | `--mv-font-ui` | 16px | 400 | line-height 1.5, max ~70ch |
| Data (CVE IDs, scores, timestamps) | `--mv-font-data` | 13px | 400 | tabular numbers |
| Hero metric (critical count) | `--mv-font-data` | 56px | 300 | |

Use uppercase only for the wordmark and severity badges. Everything else is sentence case.
Load fonts from Google Fonts with the fallbacks above.

## 4. Layout

One screen, no page scroll on a 1920×1080 viewport. Panels scroll internally.

```
+----------------------------------------------------------------------+
|  MAVIS                     status strip: feeds ● ● ●   last sync 2m  |
+---------------+--------------------------------------+---------------+
|               |                                      |               |
|  WATCHLIST    |              CORE                    |   FEED        |
|  HITS         |     (rotating ring element,          |   (new CVEs,  |
|  (ranked,     |      critical count in center)       |    KEV adds,  |
|  severity-    |                                      |    news)      |
|  colored)     +--------------------------------------+               |
|               |   DIGEST / ASK                       |               |
|               |   Gemini summary + input box         |               |
+---------------+--------------------------------------+---------------+
```

- Grid: `grid-template-columns: 320px 1fr 360px`, gap `--mv-space-5`.
- Side panels tilt very slightly toward the center (`transform: perspective(1200px) rotateY(±4deg)`)
  to suggest a curved display. Center column stays flat.
- Below 1100px wide: stack to one column in this order: Core, Watchlist hits, Digest, Feed.
  Remove the tilt.
- Text is left-aligned everywhere except the Core's center metric.

## 5. Components

### 5.1 Panel (base)
- Background `--mv-panel` with `backdrop-filter: blur(8px)`.
- Border: `--mv-line-hair` solid `--mv-panel-edge`, no border-radius.
- Corner brackets: small 12px L-shaped SVG strokes in `--mv-primary` at all four corners
  (these replace a full border look; they are the HUD's signature framing device).
- Title row: panel title left, item count right in `--mv-font-data`.

### 5.2 Core (the one memorable element)
- Inline SVG, ~360px square, centered in the middle column.
- 3 concentric rings, each built from dashed arcs (`stroke-dasharray`) in `--mv-primary-dim`,
  with one highlighted arc segment in `--mv-primary`.
- Rings rotate at different speeds and directions: 60s, 90s reverse, 140s.
- Outer ring has tick marks every 6°, longer every 30°.
- Center: count of open critical watchlist hits (hero metric), with a small label beneath
  such as "critical on your watchlist".
- **States:**
  - `idle`: slow rotation as above.
  - `thinking` (waiting on Gemini / backend): inner ring speeds to 4s per revolution and
    pulses opacity 0.6 → 1.
  - `alert` (a new critical hit arrived): ring highlights turn `--mv-sev-critical`, one
    expanding pulse ring animates outward once (600ms), then returns to idle colors while
    the center number stays red.
  - `offline` (backend unreachable): rings stop, color drops to `--mv-text-muted`, center
    text reads "Offline".
- Drive state with a single `data-state` attribute on the Core's root element.

### 5.3 Watchlist hits list
Each row:
```
[SEV BADGE]  CVE-2026-12345          EPSS 0.94   KEV
             Product / vendor matched from watchlist
             Added 3h ago
```
- Sorted by MAVIS score descending (use the backend's score; do not recompute).
- Severity badge: 2-letter code (CR / HI / MD / LO), background in the matching
  `--mv-sev-*` color at 20% opacity, text in full color.
- KEV flag shows only when the CVE is in CISA KEV; render it in `--mv-sev-critical`.
- Critical rows get a 2px left bar in `--mv-sev-critical` and `--mv-glow-crit` on the badge.
- Click a row: expands inline to show description, CVSS, EPSS percentile, references,
  and a "Ask MAVIS about this" button that pre-fills the digest input.

### 5.4 Feed
- Reverse-chronological stream of new items from NVD, KEV and news.
- Each item: source tag (NVD / KEV / News) in `--mv-font-data`, one-line title, relative time.
- New items slide in from the top (one 250ms animation per new item, not on initial load).
- Items that also match the watchlist get a small `--mv-primary` marker.

### 5.5 Digest / Ask
- Top: the latest Gemini digest, rendered as plain paragraphs (no markdown headers).
- Bottom: single-line input with placeholder "Ask MAVIS about a CVE, product or threat".
- Submit button label: "Ask". While waiting, Core enters `thinking` and the button reads
  "Thinking…".
- Responses render with a fast type-on effect (~8ms per character, skipped entirely under
  reduced motion). Show an attribution line under each answer listing which feeds the
  answer drew on.
- Voice of MAVIS: calm, concise, a little dry. Example: "Two new items on your watchlist
  since this morning. One is already being exploited in the wild, so I'd start there."
  Never cutesy, never "sir".

### 5.6 Status strip
- Top bar: wordmark left; right side shows one dot per feed (NVD, KEV, EPSS, News)
  colored `--mv-primary` when healthy, `--mv-sev-medium` when stale (>24h), and
  `--mv-sev-critical` when the last fetch failed. Hover/focus shows last fetch time.
- "Last sync" relative time.

## 6. Motion

- **Boot sequence (once per page load, ~1.8s total):**
  1. 0–400ms: background grid fades in.
  2. 300–1100ms: Core rings draw themselves (`stroke-dashoffset` animation), outer first.
  3. 900–1500ms: panel corner brackets draw, then panels fade to full opacity.
  4. 1500–1800ms: data populates; center metric counts up from 0.
- After boot, the only ambient motion is the Core rotation. Nothing else loops.
- All user-triggered transitions use `--mv-fast` or `--mv-med` with `--mv-ease`.
- Background: a faint 40px grid in `--mv-primary-dim` at 6% opacity, plus an optional
  1px horizontal scanline overlay at 3% opacity. No animated noise.

## 7. Copy and states

- Empty watchlist hits: "Nothing on your watchlist needs attention. Add products to your
  watchlist to start tracking them."
- Feed fetch failed: "Couldn't reach NVD. Showing data from {time}. Retrying in 5 min."
- Gemini error: "The digest couldn't be generated. Raw feed data is still current."
- Loading lists: skeleton rows using `--mv-primary-dim` at 30% opacity, no spinners.
- Same action, same word: the button says "Ask", the in-progress state says "Thinking…",
  the answer header says "Answer".

## 8. Accessibility floor

- Text contrast ≥ 4.5:1 against `--mv-bg` (check `--mv-text-muted` especially).
- Severity is never conveyed by color alone: always pair with the badge code.
- Visible keyboard focus: 1px `--mv-primary` outline plus `--mv-glow`.
- All decorative SVG gets `aria-hidden="true"`. The Core's center metric is real text.
- New critical alerts announce via an `aria-live="polite"` region.

## 9. Data contract (confirm against the real backend)

The frontend expects roughly these shapes. **Before building, inspect the actual backend
routes and MySQL schema in this repo and adapt to them.** Do not invent endpoints; if one
is missing, list it for the user instead of mocking it silently.

```ts
type WatchlistHit = {
  cve_id: string;          // "CVE-2026-12345"
  severity: "critical" | "high" | "medium" | "low";
  cvss: number | null;
  epss: number | null;     // 0–1 probability
  epss_percentile: number | null;
  in_kev: boolean;
  matched_product: string; // from the watchlist
  mavis_score: number;     // backend-computed ranking score
  published_at: string;    // ISO 8601
  description: string;
  references: string[];
};

type FeedItem = {
  source: "NVD" | "KEV" | "News";
  title: string;
  url: string | null;
  at: string;              // ISO 8601
  watchlist_match: boolean;
};

type FeedHealth = {
  feed: "NVD" | "KEV" | "EPSS" | "News";
  last_success_at: string | null;
  last_error: string | null;
};

type DigestAnswer = {
  text: string;
  sources: string[];       // feeds used
  generated_at: string;
};
```

## 10. Definition of done

- [ ] All colors come from the tokens in section 3.
- [ ] Layout matches section 4 at 1920×1080 with no page scroll; stacks below 1100px.
- [ ] Core supports all four `data-state` values and switches correctly.
- [ ] A critical KEV watchlist hit is the most prominent element on screen.
- [ ] Boot sequence runs once; only the Core animates after that.
- [ ] Reduced-motion mode disables loops and type-on.
- [ ] Empty, loading and error states from section 7 are implemented.
- [ ] No forbidden names or copied film assets anywhere (section 2).
- [ ] Looks clean in a 1080p screen recording.
