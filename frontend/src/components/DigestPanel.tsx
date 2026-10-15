import { useEffect, useRef, type FormEvent, type RefObject } from 'react'
import type { AskAnswer, Digest } from '../types'
import { relativeTime } from '../format'
import { useFullscreen } from '../useFullscreen'
import { useSpeech } from '../useSpeech'
import { useTypeOn } from '../useTypeOn'
import { Panel } from './Panel'
import { Skeleton } from './Skeleton'
import './DigestPanel.css'

export type DigestState =
  | { status: 'loading' }
  | { status: 'missing' }   // backend is up, but no digest has been generated yet
  | { status: 'error' }
  | { status: 'ready'; digest: Digest }

export type AskState =
  | { status: 'idle' }
  | { status: 'thinking'; question: string }
  | { status: 'error'; question: string }
  | { status: 'answered'; question: string; answer: AskAnswer }

type AskProps = {
  ask: AskState
  question: string
  onQuestionChange: (value: string) => void
  onAsk: () => void
  onClearAnswer: () => void
  inputRef: RefObject<HTMLInputElement | null>
}

type VoiceProps = {
  text: string
  label: string
  /** When this changes to a new value, `text` is spoken automatically (used for new answers) */
  autoSpeakKey?: string
}

function VoiceControls({ text, label, autoSpeakKey }: VoiceProps) {
  const { supported, voices, voice, chooseVoice, speaking, speak, stop } = useSpeech()

  // Speak each new answer once; the ref stops a voice change from replaying it.
  // Browsers allow speech only after the user has interacted; pressing Ask counts.
  const spokenKey = useRef<string | undefined>(undefined)
  useEffect(() => {
    if (autoSpeakKey && autoSpeakKey !== spokenKey.current) {
      spokenKey.current = autoSpeakKey
      speak(text)
    }
  }, [autoSpeakKey, speak, text])

  if (!supported) return null
  const english = voices.filter(v => v.lang.startsWith('en'))
  return (
    <div className="digest__voice">
      <button type="button" className="digest__button" onClick={() => (speaking ? stop() : speak(text))}>
        {speaking ? 'Stop' : label}
      </button>
      {english.length > 0 && (
        <label className="digest__voice-pick">
          <span className="visually-hidden">Voice</span>
          <select value={voice?.name} onChange={e => chooseVoice(e.target.value)}>
            {english.map(v => <option key={v.name} value={v.name}>{v.name}</option>)}
          </select>
        </label>
      )}
    </div>
  )
}

function Answer({ ask, onClear }: { ask: Exclude<AskState, { status: 'idle' }>; onClear: () => void }) {
  const typed = useTypeOn(ask.status === 'answered' ? ask.answer.text : '')
  return (
    <section className="answer" aria-live="polite">
      <header className="answer__header">
        <h3 className="answer__title">Answer</h3>
        {ask.status !== 'thinking' && (
          <button type="button" className="answer__clear data" onClick={onClear}>Back to digest</button>
        )}
      </header>
      <p className="answer__question muted">{ask.question}</p>
      {ask.status === 'thinking' && <Skeleton rows={3} />}
      {ask.status === 'error' && (
        <p className="muted">The answer couldn't be generated. Raw feed data is still current.</p>
      )}
      {ask.status === 'answered' && (
        <>
          <p className="answer__text">{typed}</p>
          <p className="digest__attribution data muted">
            {ask.answer.sources.length > 0
              ? `Drew on ${ask.answer.sources.join(', ')} (${ask.answer.cited_cve_ids.join(', ')})`
              : 'No stored CVEs cited; general background only'}
            {' · '}{ask.answer.model}
          </p>
        </>
      )}
    </section>
  )
}

function AskBox({ ask, question, onQuestionChange, onAsk, inputRef }: Omit<AskProps, 'onClearAnswer'>) {
  const thinking = ask.status === 'thinking'
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (question.trim() && !thinking) onAsk()
  }
  return (
    <form className="ask" onSubmit={submit}>
      <div className="ask__row">
        <label htmlFor="ask-input" className="visually-hidden">Ask MAVIS</label>
        <input id="ask-input" ref={inputRef} className="ask__input" type="text" maxLength={500}
               placeholder="Ask MAVIS about a CVE, product or threat" autoComplete="off"
               value={question} onChange={e => onQuestionChange(e.target.value)} />
        <button type="submit" className="digest__button" disabled={thinking || !question.trim()}>
          {thinking ? 'Thinking…' : 'Ask'}
        </button>
      </div>
      <p className="ask__note data muted">
        Your question and public CVE data go to Gemini. Your watchlist and scores stay here.
      </p>
    </form>
  )
}

/** Spec 5.5: the latest Gemini digest (or the latest answer) with spoken briefing and the Ask box. */
export function DigestPanel({ state, ...askProps }: { state: DigestState } & AskProps) {
  const { ask, onClearAnswer } = askProps
  // Speak the answer when there is one, otherwise the digest summary. Both are Gemini's
  // own text, which is already allowed off the machine; never local matches or scores.
  const spoken = ask.status === 'answered' ? ask.answer.text
    : state.status === 'ready' ? state.digest.summary : null

  const fullscreen = useFullscreen<HTMLElement>()
  const fullscreenButton = fullscreen.supported && (
    <button type="button" className="digest__fullscreen data" onClick={fullscreen.toggle}
            aria-pressed={fullscreen.active}>
      {fullscreen.active ? 'Exit full screen' : 'Full screen'}
    </button>
  )

  return (
    <Panel title="Digest" className="digest" footer={<AskBox {...askProps} />}
           actions={fullscreenButton} panelRef={fullscreen.ref}>
      {spoken && (
        <VoiceControls text={spoken} label={ask.status === 'answered' ? 'Read answer' : 'Brief me'}
                       autoSpeakKey={ask.status === 'answered' ? ask.answer.generated_at : undefined} />
      )}
      {ask.status !== 'idle' && <Answer ask={ask} onClear={onClearAnswer} />}
      {ask.status === 'idle' && (
        <>
          {state.status === 'loading' && <Skeleton rows={4} />}
          {state.status === 'error' && (
            <p className="muted">The digest couldn't be generated. Raw feed data is still current.</p>
          )}
          {state.status === 'missing' && (
            <p className="muted">No briefing yet. Run <code className="data">python cli.py brief</code> to create one.</p>
          )}
          {state.status === 'ready' && (
            <>
              <div className="digest__text">
                <p>{state.digest.summary}</p>
                {state.digest.items.map(item => (
                  <p key={item.cve_id}>
                    <span className="data digest__cve">{item.cve_id}</span>{' '}
                    <span className="data muted">{item.urgency}</span>{' '}
                    {item.headline}. {item.what_it_is} {item.action}
                  </p>
                ))}
              </div>
              <p className="digest__attribution data muted">
                Drew on {state.digest.sources.join(', ')} · {state.digest.model} · {relativeTime(state.digest.generated_at)}
              </p>
            </>
          )}
        </>
      )}
    </Panel>
  )
}
