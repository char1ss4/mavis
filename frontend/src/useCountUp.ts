import { useEffect, useRef, useState } from 'react'

const BOOT_DATA_AT_MS = 1500 // spec 6: data populates 1500-1800ms after page load
const DURATION_MS = 300

export const prefersReducedMotion = () =>
  typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

/**
 * Counts up from 0 to `target` once, at the end of the boot sequence.
 * Later changes to `target` jump straight to the new value.
 */
export function useCountUp(target: number): number {
  const [value, setValue] = useState(0)
  const done = useRef(false)

  useEffect(() => {
    // Already counted once (or motion is reduced): just show the number
    if (done.current || prefersReducedMotion()) {
      setValue(target)
      return
    }
    if (target === 0) return // data hasn't arrived yet; count up when it does
    let frame = 0
    const startAt = Math.max(0, BOOT_DATA_AT_MS - performance.now())
    const timer = window.setTimeout(() => {
      const started = performance.now()
      const tick = (now: number) => {
        const progress = Math.min(1, (now - started) / DURATION_MS)
        setValue(Math.round(target * progress))
        if (progress < 1) frame = requestAnimationFrame(tick)
        else done.current = true
      }
      frame = requestAnimationFrame(tick)
    }, startAt)
    return () => { window.clearTimeout(timer); cancelAnimationFrame(frame) }
  }, [target])

  return value
}
