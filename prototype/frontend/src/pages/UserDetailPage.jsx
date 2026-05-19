import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import SingleResult from '../components/SingleResult'

export default function UserDetailPage() {
  const { state }  = useLocation()
  const navigate   = useNavigate()
  const [detail, setDetail]   = useState(null)
  const [loading, setLoading] = useState(true)

  const row = state?.row

  useEffect(() => {
    if (!row) { navigate('/'); return }

    async function fetchDetail() {
      try {
        const res  = await fetch('/api/explain', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify(row.record),
        })
        const data = await res.json()
        setDetail(res.ok ? { ...row, ...data } : row)
      } catch {
        setDetail(row)
      } finally {
        setLoading(false)
      }
    }

    fetchDetail()
  }, []) 

  if (!row) return null

  const mal       = row.prediction === 1
  const threatPct = (row.probability * 100).toFixed(1)

  return (
    <div>
      {/* ── Header bar ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
        <button className="btn btn-secondary" onClick={() => navigate(-1)}>
          ← Back to Results
        </button>
        <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
          User{' '}
          <strong style={{ color: 'var(--gold)' }}>#{row.rank}</strong>
          {' · '}
          <strong style={{ color: mal ? '#e55' : '#5c5' }}>
            {mal ? 'MALICIOUS' : 'NORMAL'}
          </strong>
          {' · '}
          <span style={{ color: 'var(--text-dim)' }}>{threatPct}% threat score</span>
        </span>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--gold)' }}>
          Loading user details…
        </div>
      ) : (
        <SingleResult result={detail} onBack={null} />
      )}
    </div>
  )
}
