import { useEffect, useState } from 'react'
import { prefersReducedMotion } from './useCountUp'

const MS_PER_CHAR = 8 // spec 5.5: fast type-on, ~8ms per character

/** Reveals `text` a character at a time; shows it all at once under reduced motion. */
export function useTypeOn(text: string): string {
  // Progress is stored with the text it belongs to, so a new text starts from 0
  const [progress, setProgress] = useState({ text: '', chars: 0 })
  const reduced = prefersReducedMotion()

  useEffect(() => {
    if (reduced) return
    let frame = 0
    const started = performance.now()
    const tick = (now: number) => {
      const chars = Math.min(text.length, Math.floor((now - started) / MS_PER_CHAR))
      setProgress({ text, chars })
      if (chars < text.length) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [text, reduced])

  if (reduced) return text
  return text.slice(0, progress.text === text ? progress.chars : 0)
}
