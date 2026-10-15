/** Loading placeholder (spec section 7): dim bars, no spinners. */
export function Skeleton({ rows }: { rows: number }) {
  return (
    <div aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} style={{
          height: 14,
          width: `${90 - (i % 3) * 15}%`,
          margin: 'var(--mv-space-3) 0',
          background: 'var(--mv-primary-dim)',
          opacity: 0.3,
        }} />
      ))}
    </div>
  )
}
