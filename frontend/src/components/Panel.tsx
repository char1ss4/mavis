import type { ReactNode } from 'react'
import './Panel.css'

type PanelProps = {
  title: string
  count?: number | string
  className?: string
  children: ReactNode
}

/** The 12px L-shaped stroke drawn in each corner; rotated per corner by CSS. */
function CornerBracket({ corner }: { corner: 'tl' | 'tr' | 'bl' | 'br' }) {
  return (
    <svg className={`panel__corner panel__corner--${corner}`} width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
      <path d="M0.75 12 V0.75 H12" fill="none" />
    </svg>
  )
}

/** Base glass panel (spec 5.1): title left, item count right, corner brackets, scrolling body. */
export function Panel({ title, count, className = '', children }: PanelProps) {
  return (
    <section className={`panel ${className}`} aria-label={title}>
      <CornerBracket corner="tl" />
      <CornerBracket corner="tr" />
      <CornerBracket corner="bl" />
      <CornerBracket corner="br" />
      <header className="panel__header">
        <h2 className="panel__title">{title}</h2>
        {count !== undefined && <span className="panel__count data">{count}</span>}
      </header>
      <div className="panel__body">{children}</div>
    </section>
  )
}
