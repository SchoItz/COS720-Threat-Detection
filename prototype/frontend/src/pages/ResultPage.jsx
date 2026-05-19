import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import SingleResult from '../components/SingleResult'


function bandLabel(pct) {
  if (pct >= 65) return 'Malicious'
  if (pct >= 45) return 'Suspicious'
  if (pct >= 40) return 'Borderline'
  return 'Not-suspicious'
}

const BAND_COLOR = {
  Malicious:        'var(--danger)',
  Suspicious:       'var(--warning)',
  Borderline:       'var(--caution)',
  'Not-suspicious': 'var(--success)',
}

const BAND_BG = {
  Malicious:        'var(--danger-dim)',
  Suspicious:       'var(--warning-dim)',
  Borderline:       'var(--caution-dim)',
  'Not-suspicious': 'var(--success-dim)',
}

const FILTERS = ['All', 'Malicious', 'Suspicious', 'Borderline']

export default function ResultPage() {
  const { state }                       = useLocation()
  const navigate                        = useNavigate()
  const [activeFilter, setActiveFilter] = useState('All')
  const [showFPN, setShowFPN]           = useState(false)

  useEffect(() => {
    const savedY = sessionStorage.getItem('resultScrollY')
    if (savedY) {
      window.scrollTo(0, parseInt(savedY, 10))
      sessionStorage.removeItem('resultScrollY')
    }
  }, [])

  useEffect(() => {
    if (!state?.result) navigate('/')
  }, [state, navigate])

  const result = state?.result
  if (!result) return null


  if (Array.isArray(result.results)) {
    const rows = result.results

    const labeledRows = rows.map(r => {
      const pct = Math.round(r.probability * 100)
      const lbl = bandLabel(pct)
      return { ...r, _pct: pct, _label: lbl }
    })

    const counts = {}
    FILTERS.slice(1).forEach(f => {
      counts[f] = labeledRows.filter(r => r._label === f).length
    })

    const filteredRows = activeFilter === 'All'
      ? labeledRows
      : labeledRows.filter(r => r._label === activeFilter)


    const hasFPN = !!result.has_ground_truth
    const fpRows = hasFPN ? labeledRows.filter(r => r.actual_label === 0) : []
    const fnRows = hasFPN
      ? (result.false_negatives || []).map(r => ({
          ...r,
          _pct:  Math.round(r.probability * 100),
          _label: bandLabel(Math.round(r.probability * 100)),
          _isFN: true,
        }))
      : []
    const fpnRows    = [...fpRows, ...fnRows]
    const displayRows = showFPN ? fpnRows : filteredRows

    function handleRowClick(r) {
      sessionStorage.setItem('resultScrollY', String(window.scrollY))
      navigate('/result/user', { state: { row: r, from: state } })
    }

    return (
      <div>
    
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
          <button className="btn btn-secondary" onClick={() => navigate('/')}>
            ← Back to Analysis
          </button>
          <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
            CSV Batch &mdash;&nbsp;
            <strong style={{ color: 'var(--text-dim)' }}>{result.total_records ?? rows.length}</strong> scanned
            &nbsp;·&nbsp;
            <strong style={{ color: 'var(--danger)' }}>{counts.Malicious ?? 0}</strong> malicious
            &nbsp;·&nbsp;
            <strong style={{ color: 'var(--warning)' }}>{counts.Suspicious ?? 0}</strong> suspicious
            &nbsp;·&nbsp;
            <strong style={{ color: 'var(--caution)' }}>{counts.Borderline ?? 0}</strong> borderline
            {result.saved_at && (
              <span style={{ marginLeft: '0.75rem', opacity: 0.5, fontSize: '0.75rem' }}>
                saved {new Date(result.saved_at).toLocaleString()}
              </span>
            )}
          </span>
        </div>

      
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1.25rem', alignItems: 'center' }}>
          {FILTERS.map(f => {
            const active  = !showFPN && activeFilter === f
            const fColor  = f === 'All' ? 'var(--text-dim)' : BAND_COLOR[f]
            const activeBg = f === 'All' ? 'rgba(180,180,180,0.12)' : BAND_BG[f]
            const count   = f === 'All' ? rows.length : (counts[f] ?? 0)
            return (
              <button
                key={f}
                onClick={() => { setActiveFilter(f); setShowFPN(false) }}
                style={{
                  padding: '0.3rem 0.85rem',
                  borderRadius: '99px',
                  border: `1.5px solid ${active ? fColor : 'var(--border)'}`,
                  background: active ? activeBg : 'transparent',
                  color: active ? fColor : 'var(--text-dim)',
                  fontSize: '0.78rem',
                  fontWeight: active ? 700 : 500,
                  cursor: 'pointer',
                  transition: 'all 0.15s',
                }}
              >
                {f} <span style={{ opacity: 0.65 }}>({count})</span>
              </button>
            )
          })}

          {hasFPN && (
            <button
              onClick={() => setShowFPN(v => !v)}
              style={{
                padding: '0.3rem 0.85rem',
                borderRadius: '99px',
                border: `1.5px solid ${showFPN ? 'var(--warning)' : 'var(--border)'}`,
                background: showFPN ? 'var(--warning-dim)' : 'transparent',
                color: showFPN ? 'var(--warning)' : 'var(--text-dim)',
                fontSize: '0.78rem',
                fontWeight: showFPN ? 700 : 500,
                cursor: 'pointer',
                transition: 'all 0.15s',
                marginLeft: '0.25rem',
              }}
            >
              False Positives ({result.false_positive_count ?? 0})
              &nbsp;/&nbsp;
              Negatives ({result.false_negative_count ?? 0})
            </button>
          )}
        </div>

   
        <div className="card" style={{ marginBottom: '1.5rem', padding: 0, overflow: 'hidden' }}>
          {displayRows.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.9rem' }}>
              {showFPN ? 'No false positives or negatives found.' : `No ${activeFilter.toLowerCase()} results found.`}
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)' }}>
                  {(showFPN
                    ? ['Type', 'Verdict', 'Threat Score', 'Actual', 'CSV Row', '']
                    : ['Rank', 'Verdict', 'Threat Score', 'High', 'Med', 'Low', 'CSV Row', '']
                  ).map(h => (
                    <th key={h} style={{ padding: '0.65rem 1rem', textAlign: 'left', color: 'var(--text-dim)', fontWeight: 600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayRows.map((r, i) => {
                  const isFP = showFPN && !r._isFN && r.actual_label === 0
                  const isFN = showFPN && !!r._isFN
                  const clr  = isFP ? 'var(--warning)' : isFN ? 'var(--danger)' : BAND_COLOR[r._label]
                  const bg   = isFP ? 'var(--warning-dim)' : isFN ? 'var(--danger-dim)' : BAND_BG[r._label]
                  return (
                    <tr
                      key={i}
                      onClick={() => handleRowClick(r)}
                      style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer', transition: 'background 0.15s' }}
                      onMouseEnter={e => e.currentTarget.style.background = 'var(--surface)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      {showFPN ? (
                        <td style={{ padding: '0.6rem 1rem' }}>
                          <span style={{
                            display: 'inline-block', padding: '0.2rem 0.55rem',
                            borderRadius: '4px', fontSize: '0.7rem', fontWeight: 700,
                            background: bg, color: clr, letterSpacing: '0.04em',
                          }}>
                            {isFP ? 'FALSE POSITIVE' : 'FALSE NEGATIVE'}
                          </span>
                        </td>
                      ) : (
                        <td style={{ padding: '0.6rem 1rem', color: 'var(--gold)', fontWeight: 700 }}>#{r.rank}</td>
                      )}
                      <td style={{ padding: '0.6rem 1rem' }}>
                        <span style={{
                          display: 'inline-block', padding: '0.2rem 0.6rem',
                          borderRadius: '4px', fontSize: '0.75rem', fontWeight: 700,
                          background: BAND_BG[r._label], color: BAND_COLOR[r._label],
                        }}>
                          {r._label.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '0.6rem 1rem' }}>
                        <span style={{ color: BAND_COLOR[r._label], fontWeight: 700 }}>{r._pct}%</span>
                      </td>
                      {showFPN ? (
                        <td style={{ padding: '0.6rem 1rem', fontSize: '0.75rem', fontWeight: 600,
                          color: isFN ? 'var(--danger)' : 'var(--success)' }}>
                          {isFN ? 'Malicious' : 'Normal'}
                        </td>
                      ) : (
                        <>
                          <td style={{ padding: '0.6rem 1rem', color: 'var(--danger)' }}>{r.high_risk_count ?? 0}</td>
                          <td style={{ padding: '0.6rem 1rem', color: 'var(--warning)' }}>{r.medium_risk_count ?? 0}</td>
                          <td style={{ padding: '0.6rem 1rem', color: 'var(--text-dim)' }}>{r.low_risk_count ?? 0}</td>
                        </>
                      )}
                      <td style={{ padding: '0.6rem 1rem', color: 'var(--text-dim)', fontSize: '0.75rem' }}>{r.row_index}</td>
                      <td style={{ padding: '0.6rem 1rem', color: 'var(--gold)', fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                        View →
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    )
  }


  return <SingleResult result={result} onBack={() => navigate('/')} />
}
