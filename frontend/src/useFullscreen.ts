import { useCallback, useEffect, useRef, useState } from 'react'

/** Browser full-screen mode for one element. Esc (handled by the browser) also exits. */
export function useFullscreen<T extends HTMLElement>() {
  const ref = useRef<T>(null)
  const [active, setActive] = useState(false)

  useEffect(() => {
    // Also fires when the user leaves with Esc, so the button label stays correct
    const sync = () => setActive(document.fullscreenElement !== null && document.fullscreenElement === ref.current)
    document.addEventListener('fullscreenchange', sync)
    return () => document.removeEventListener('fullscreenchange', sync)
  }, [])

  const toggle = useCallback(() => {
    if (document.fullscreenElement) void document.exitFullscreen()
    else void ref.current?.requestFullscreen()
  }, [])

  return { ref, active, toggle, supported: typeof document !== 'undefined' && document.fullscreenEnabled }
}
