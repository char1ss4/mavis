import type { Digest } from '../types'
import { relativeTime } from '../format'
import { useSpeech } from '../useSpeech'
import { Panel } from './Panel'
import { Skeleton } from './Skeleton'
import './DigestPanel.css'

export type DigestState =
  | { status: 'loading' }
  | { status: 'missing' }   // backend is up, but no digest has been generated yet
  | { status: 'error' }
  | { status: 'ready'; digest: Digest }

function VoiceControls({ text }: { text: string }) {
  const { supported, voices, voice, chooseVoice, speaking, speak, stop } = useSpeech()
  if (!supported) return null
  const english = voices.filter(v => v.lang.startsWith('en'))
  return (
    <div className="digest__voice">
      <button type="button" className="digest__speak" onClick={() => (speaking ? stop() : speak(text))}>
        {speaking ? 'Stop' : 'Brief me'}
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

/** Spec 5.5, first half: the latest Gemini digest as plain paragraphs, plus spoken briefing. */
export function DigestPanel({ state }: { state: DigestState }) {
  return (
    <Panel title="Digest" className="digest">
      {state.status === 'loading' && <Skeleton rows={4} />}
      {state.status === 'error' && (
        <p className="muted">The digest couldn't be generated. Raw feed data is still current.</p>
      )}
      {state.status === 'missing' && (
        <p className="muted">No briefing yet. Run <code className="data">python cli.py brief</code> to create one.</p>
      )}
      {state.status === 'ready' && (
        <>
          {/* Only Gemini's own summary is spoken: it's already allowed off the machine */}
          <VoiceControls text={state.digest.summary} />
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
    </Panel>
  )
}
