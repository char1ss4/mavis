import { useCallback, useEffect, useState } from 'react'

const STORAGE_KEY = 'mavis.voice'

function loadSavedVoice(): string | null {
  try { return localStorage.getItem(STORAGE_KEY) } catch { return null }
}

function saveVoice(name: string) {
  try { localStorage.setItem(STORAGE_KEY, name) } catch { /* private window: just don't remember it */ }
}

/** Prefer a saved voice, then Edge's online "Natural" English voices, then British, then any English. */
function pickDefault(voices: SpeechSynthesisVoice[]): SpeechSynthesisVoice | undefined {
  const saved = loadSavedVoice()
  return voices.find(v => v.name === saved)
    ?? voices.find(v => v.name.includes('Natural') && v.lang === 'en-GB')
    ?? voices.find(v => v.name.includes('Natural') && v.lang.startsWith('en'))
    ?? voices.find(v => v.lang === 'en-GB')
    ?? voices.find(v => v.lang.startsWith('en'))
    ?? voices[0]
}

/**
 * Text-to-speech through the browser's Web Speech API.
 *
 * Privacy: "Natural" voices are online, so the browser sends the text to its speech service.
 * Only pass Gemini's digest text here (already allowed out), never watchlist matches or scores.
 */
export function useSpeech() {
  const supported = typeof window !== 'undefined' && 'speechSynthesis' in window
  const [voices, setVoices] = useState<SpeechSynthesisVoice[]>([])
  const [voice, setVoice] = useState<SpeechSynthesisVoice>()
  const [speaking, setSpeaking] = useState(false)

  useEffect(() => {
    if (!supported) return
    // Voices load asynchronously; Chrome and Edge fire 'voiceschanged' when they're ready
    const load = () => {
      const available = speechSynthesis.getVoices()
      setVoices(available)
      setVoice(current => current ?? pickDefault(available))
    }
    load()
    speechSynthesis.addEventListener('voiceschanged', load)
    return () => {
      speechSynthesis.removeEventListener('voiceschanged', load)
      speechSynthesis.cancel()
    }
  }, [supported])

  const chooseVoice = useCallback((name: string) => {
    const chosen = voices.find(v => v.name === name)
    if (chosen) { setVoice(chosen); saveVoice(name) }
  }, [voices])

  const speak = useCallback((text: string) => {
    if (!supported) return
    speechSynthesis.cancel() // stop anything already playing
    const utterance = new SpeechSynthesisUtterance(text)
    if (voice) utterance.voice = voice
    utterance.rate = 0.95 // a touch slower reads as calmer
    utterance.onstart = () => setSpeaking(true)
    utterance.onend = () => setSpeaking(false)
    utterance.onerror = () => setSpeaking(false)
    speechSynthesis.speak(utterance)
  }, [supported, voice])

  const stop = useCallback(() => {
    if (supported) speechSynthesis.cancel()
    setSpeaking(false)
  }, [supported])

  return { supported, voices, voice, chooseVoice, speaking, speak, stop }
}
