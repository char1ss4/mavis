import { useCountUp } from '../useCountUp'
import './Core.css'

export type CoreState = 'idle' | 'thinking' | 'alert' | 'offline'

const C = 180 // centre of the 360x360 viewBox

/** Tick marks every 6 degrees on the outer ring, longer every 30. */
const TICKS = Array.from({ length: 60 }, (_, i) => {
  const angle = (i * 6 * Math.PI) / 180
  const inner = i % 5 === 0 ? 160 : 166
  return {
    key: i,
    x1: C + inner * Math.cos(angle), y1: C + inner * Math.sin(angle),
    x2: C + 172 * Math.cos(angle), y2: C + 172 * Math.sin(angle),
  }
})

type RingProps = { name: 'outer' | 'middle' | 'inner'; r: number; dashes: string; arcDegrees: number }

/**
 * One ring: a faint guide circle (drawn in during boot), the dashed ring itself,
 * and one highlighted arc. pathLength="360" lets the arc be sized in degrees.
 */
function Ring({ name, r, dashes, arcDegrees }: RingProps) {
  return (
    <g className={`core__ring core__ring--${name}`}>
      <circle className="core__guide" cx={C} cy={C} r={r} pathLength={1} />
      <circle className="core__dashes" cx={C} cy={C} r={r} strokeDasharray={dashes} />
      <circle className="core__highlight" cx={C} cy={C} r={r} pathLength={360}
              strokeDasharray={`${arcDegrees} ${360 - arcDegrees}`} />
    </g>
  )
}

type CoreProps = {
  state: CoreState
  count: number | null
  /** After a critical alert the number stays red until the page reloads (spec 5.2). */
  alerted: boolean
}

/** The Core (spec 5.2): rotating rings with the open critical watchlist count in the middle. */
export function Core({ state, count, alerted }: CoreProps) {
  const shown = useCountUp(count ?? 0)
  const offline = state === 'offline'
  return (
    <section className="core" data-state={state} aria-label="Critical watchlist hits">
      <div className="core__frame">
        <svg className="core__svg" viewBox="0 0 360 360" aria-hidden="true">
          <g className="core__ring core__ring--outer">
            <circle className="core__guide" cx={C} cy={C} r={172} pathLength={1} />
            {TICKS.map(t => <line key={t.key} className="core__tick" x1={t.x1} y1={t.y1} x2={t.x2} y2={t.y2} />)}
          </g>
          <Ring name="outer" r={150} dashes="2 6" arcDegrees={60} />
          <Ring name="middle" r={126} dashes="14 8" arcDegrees={90} />
          <Ring name="inner" r={102} dashes="1 4" arcDegrees={40} />
          {/* Remounted on each alert so the 600ms pulse plays once */}
          {state === 'alert' && <circle className="core__pulse" cx={C} cy={C} r={102} />}
        </svg>
        <div className="core__centre">
          <div className={`core__metric data ${alerted ? 'core__metric--alert' : ''}`}>
            {offline ? 'Offline' : count === null ? '-' : shown}
          </div>
          {!offline && <div className="core__label">critical on your watchlist</div>}
        </div>
      </div>
    </section>
  )
}
