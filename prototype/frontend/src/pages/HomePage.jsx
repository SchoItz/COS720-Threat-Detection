import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'

const NUMERIC_FIELDS = [
  { key: 'employee_seniority_years',      label: 'Seniority (Years)',           min: 0, step: 1, default: 5  },
  { key: 'total_files_burned',            label: 'Total Files Burned',          min: 0, step: 1, default: 0  },
  { key: 'burned_from_other',             label: 'Files Burned (Other Source)', min: 0, step: 1, default: 0  },
  { key: 'num_printed_pages_off_hours',   label: 'Off-Hours Print Pages',       min: 0, step: 1, default: 0  },
  { key: 'total_printed_pages',           label: 'Total Print Pages',           min: 0, step: 1, default: 10 },
  { key: 'num_entries',                   label: 'Building Entries',            min: 0, step: 1, default: 2  },
  { key: 'late_exit_flag',                label: 'Late Exit Count',             min: 0, step: 1, default: 0  },
  { key: 'entry_during_weekend',          label: 'Weekend Entries',             min: 0, step: 1, default: 0  },
  { key: 'trip_day_number',               label: 'Trip Duration (Days)',        min: 0, step: 1, default: 0  },
  { key: 'hostility_country_level',       label: 'Travel Country Risk (1–5)',   min: 1, step: 1, default: 1  },
]

const DEPT_OPTIONS  = ['R&D', 'Finance', 'IT', 'Engineering', 'Operations', 'HR', 'Legal', 'Sales', 'Marketing']
const CLASS_OPTIONS = ['Level 1', 'Level 2', 'Level 3', 'Level 4', 'Level 5']

const SAMPLE_CARDS = [
  { id: 1, name: 'Francois Scholtz',  title: 'Normal Employee: Standard Activity',            badge: 'Not-suspicious' },
  { id: 2, name: 'Friedrich Lauchner',   title: 'Suspicious Activity: Borderline Case',          badge: 'Borderline' },
  { id: 3, name: 'Alden Peach',  title: 'High-Risk: Clear Malicious Indicators',         badge: 'Malicious'  },
  { id: 4, name: 'Galen Myburgh',     title: 'False Positive Risk: Authorised Heavy Usage',   badge: 'Suspicious' },
  { id: 5, name: 'Hendre Beyer',    title: 'IT Contractor: Elevated Access Flags',          badge: 'Suspicious' },
]

function initForm() {
  const d = {}
  NUMERIC_FIELDS.forEach(f => { d[f.key] = f.default })
  d.employee_department     = 'R&D'
  d.employee_classification = 'Level 3'
  d.is_contractor           = 0
  d.has_criminal_record     = 0
  return d
}

export default function HomePage() {
  const navigate = useNavigate()
  const [tab, setTab]             = useState('form')
  const [form, setForm]           = useState(initForm)
  const [file, setFile]           = useState(null)
  const [dragOver, setDragOver]   = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [csvProgress, setCsvProgress] = useState(0)
  const [loadingSample, setLoadingSample] = useState(null)
  const [error, setError]         = useState(null)
  const fileRef = useRef()
  const progressRef = useRef(null)

  function setNum(key, val) {
    setForm(prev => ({ ...prev, [key]: val }))
  }

  async function handleFormSubmit(e) {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      const body = {}
      NUMERIC_FIELDS.forEach(f => { body[f.key] = parseFloat(form[f.key]) || 0 })
      body.employee_department     = form.employee_department
      body.employee_classification = form.employee_classification
      body.is_contractor           = parseInt(form.is_contractor, 10)
      body.has_criminal_record     = parseInt(form.has_criminal_record, 10)

      const res  = await fetch('/api/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Prediction failed.')
      navigate('/result', { state: { result: data } })
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  async function handleCSVSubmit(e) {
    e.preventDefault()
    if (!file) { setError('Please select a CSV file first.'); return }
    setSubmitting(true)
    setCsvProgress(0)
    setError(null)

    
    let current = 0
    progressRef.current = setInterval(() => {
      if (current < 80) {
        current += Math.random() * 2.5 + 0.5
      } else {
       
        current += (98 - current) * 0.012
      }
      setCsvProgress(Math.round(Math.min(current, 98)))
    }, 150)

    try {
      const fd = new FormData()
      fd.append('csv_file', file)
      const res  = await fetch('/api/predict', { method: 'POST', body: fd })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Prediction failed.')
      clearInterval(progressRef.current)
      setCsvProgress(100)
      setTimeout(() => navigate('/result', { state: { result: data } }), 400)
    } catch (err) {
      clearInterval(progressRef.current)
      setCsvProgress(0)
      const msg = err.message || ''
      if (msg.toLowerCase().includes('failed to fetch') || msg.toLowerCase().includes('networkerror') || msg.toLowerCase().includes('load failed')) {
        setError('Cannot reach the analysis server. Make sure Flask is running on port 5000, then refresh and try again.')
      } else {
        setError(msg || 'Prediction failed.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  function handleDrop(e) {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files[0]
    if (f && f.name.toLowerCase().endsWith('.csv')) setFile(f)
    else setError('Drag and drop a valid .csv file.')
  }

  async function loadSavedResults() {
    setSubmitting(true)
    setError(null)
    try {
      const res  = await fetch('/api/malicious')
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to load saved results.')
      navigate('/result', { state: { result: data } })
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  async function loadSample(id) {
    setLoadingSample(id)
    setError(null)
    try {
      const res  = await fetch(`/api/sample/${id}`)
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to load sample.')
      navigate('/result', { state: { result: data } })
    } catch (err) {
      setError(err.message)
    } finally {
      setLoadingSample(null)
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          AI-Powered <span className="gold-accent">Insider Threat</span> Detection
        </h1>
        <p className="page-subtitle">
          Enter employee activity data manually, upload a CSV, or click a sample profile to see the model in action.
        </p>
      </div>

      {error && (
        <div className="alert alert-error">
          <span>{error}</span>
        </div>
      )}

      <div className="home-grid">
        
        <div className="card">
          <div className="tabs">
            <button className={`tab-btn${tab === 'form' ? ' active' : ''}`} onClick={() => setTab('form')}>
              Manual Entry
            </button>
            <button className={`tab-btn${tab === 'csv' ? ' active' : ''}`} onClick={() => setTab('csv')}>
              CSV Upload
            </button>
          </div>

          {tab === 'form' ? (
            <form onSubmit={handleFormSubmit}>
              <div className="form-grid">
                {NUMERIC_FIELDS.map(f => (
                  <div className="form-group" key={f.key}>
                    <label className="form-label">{f.label}</label>
                    <input
                      type="number"
                      className="form-input"
                      value={form[f.key]}
                      min={f.min}
                      step={f.step}
                      onChange={e => setNum(f.key, e.target.value)}
                    />
                  </div>
                ))}

                <div className="form-group">
                  <label className="form-label">Department</label>
                  <select
                    className="form-select"
                    value={form.employee_department}
                    onChange={e => setForm(p => ({ ...p, employee_department: e.target.value }))}
                  >
                    {DEPT_OPTIONS.map(d => <option key={d}>{d}</option>)}
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Classification</label>
                  <select
                    className="form-select"
                    value={form.employee_classification}
                    onChange={e => setForm(p => ({ ...p, employee_classification: e.target.value }))}
                  >
                    {CLASS_OPTIONS.map(c => <option key={c}>{c}</option>)}
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Contractor</label>
                  <select
                    className="form-select"
                    value={form.is_contractor}
                    onChange={e => setForm(p => ({ ...p, is_contractor: parseInt(e.target.value, 10) }))}
                  >
                    <option value={0}>No (Permanent)</option>
                    <option value={1}>Yes (Contractor)</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Criminal Record on File</label>
                  <select
                    className="form-select"
                    value={form.has_criminal_record}
                    onChange={e => setForm(p => ({ ...p, has_criminal_record: parseInt(e.target.value, 10) }))}
                  >
                    <option value={0}>No</option>
                    <option value={1}>Yes</option>
                  </select>
                </div>
              </div>

              <button type="submit" className="btn btn-primary" disabled={submitting} style={{ width: '100%' }}>
                {submitting ? 'Analysing…' : 'Run Threat Analysis'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleCSVSubmit}>
              <div
                className={`upload-area${dragOver ? ' drag-over' : ''}`}
                onClick={() => fileRef.current.click()}
                onDragOver={e => { e.preventDefault(); setDragOver(true) }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
              >
                {file ? (
                  <>
                    <div style={{ color: 'var(--gold)', fontWeight: 600 }}>{file.name}</div>
                    <div className="upload-hint">Click to select file</div>
                  </>
                ) : (
                  <>
                    <div className="upload-text">Drag &amp; drop a CSV, or click to browse</div>
                    
                  </>
                )}
              </div>

              <input
                ref={fileRef}
                type="file"
                accept=".csv"
                style={{ display: 'none' }}
                onChange={e => setFile(e.target.files[0] || null)}
              />

              <div className="upload-hint" style={{ marginBottom: '1rem' }}>
                Required columns: employee_seniority_years, total_files_burned, burned_from_other,
                num_printed_pages_off_hours, total_printed_pages, num_entries, late_exit_flag,
                entry_during_weekend, trip_day_number, hostility_country_level,
                employee_department, employee_classification, is_contractor,
                has_criminal_record
              </div>

              {submitting && (
                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                    <span>Analysing records…</span>
                    <span style={{ color: 'var(--gold)', fontWeight: 600 }}>{csvProgress}%</span>
                  </div>
                  <div style={{ height: '8px', borderRadius: '4px', background: 'var(--surface)', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%',
                      width: `${csvProgress}%`,
                      borderRadius: '4px',
                      background: csvProgress === 100
                        ? '#5c5'
                        : 'linear-gradient(90deg, var(--gold), #f0c040)',
                      transition: 'width 0.15s ease-out',
                    }} />
                  </div>
                </div>
              )}

              <button
                type="submit"
                className="btn btn-primary"
                disabled={submitting || !file}
                style={{ width: '100%' }}
              >
                {submitting ? `Analysing… ${csvProgress}%` : 'Analyse CSV'}
              </button>

              <button
                type="button"
                className="btn btn-secondary"
                disabled={submitting}
                onClick={loadSavedResults}
                style={{ width: '100%', marginTop: '0.6rem' }}
              >
                Load Previous Malicious Results
              </button>
            </form>
          )}
        </div>

   
        <div className="samples-section">
          <h2>Sample Profiles</h2>
          <p>Click any profile to run a pre-filled prediction</p>

          <div className="samples-list">
            {SAMPLE_CARDS.map(p => (
              <div
                key={p.id}
                className={`sample-card${loadingSample === p.id ? ' loading' : ''}`}
                onClick={() => loadSample(p.id)}
              >
                <span className={`sample-badge badge-${p.badge}`}>{p.badge}</span>
                <div>
                  <div className="sample-name">{p.name}</div>
                  <div className="sample-title">{p.title}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
