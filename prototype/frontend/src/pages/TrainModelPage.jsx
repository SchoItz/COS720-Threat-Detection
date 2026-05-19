import { useState, useRef } from 'react'

export default function TrainModelPage() {
  const [file, setFile]           = useState(null)
  const [dragOver, setDragOver]   = useState(false)
  const [training, setTraining]   = useState(false)
  const [metrics, setMetrics]     = useState(null)
  const [error, setError]         = useState(null)
  const fileRef = useRef()


  function handleDrop(e) {
    e.preventDefault()
    setDragOver(false)
    const dropped = e.dataTransfer.files[0]
    if (dropped && dropped.name.toLowerCase().endsWith('.csv')) {
      setFile(dropped)
      setError(null)
      setMetrics(null)
    } else {
      setError('Drag and drop a valid CSV file.')
    }
  }

  function handleFileChange(e) {
    const chosen = e.target.files[0]
    if (chosen) {
      setFile(chosen)
      setError(null)
      setMetrics(null)
    }
  }


  async function handleTrain(e) {
    e.preventDefault()
    if (!file) { setError('No CSV file selected.'); return }

    setTraining(true)
    setError(null)
    setMetrics(null)

    try {
      const formData = new FormData()
      formData.append('csv_file', file)

      const res  = await fetch('/api/train', { method: 'POST', body: formData })
      const data = await res.json()

      if (!res.ok) throw new Error(data.error || 'Training failed.')
      setMetrics(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setTraining(false)
    }
  }

  function cmCellStyle(row, col, cm) {
    const max = Math.max(...cm.flat())
    const val = cm[row][col]
    const intensity = max > 0 ? val / max : 0
    if (row === col) {
    
      return {
        background: `rgba(82,184,82,${0.12 + intensity * 0.55})`,
        color: 'var(--text)',
      }
    }
 
    return {
      background: val > 0 ? `rgba(224,82,82,${0.12 + intensity * 0.55})` : 'transparent',
      color: 'var(--text)',
    }
  }

  const pct = v => `${(v * 100).toFixed(2)}%`

  return (
    <div className="train-page">
      <div className="page-header" style={{ marginBottom: '2rem' }}>
        <h1 className="page-title">Train Model</h1>
        <p className="page-subtitle">
          Upload a labelled CSV dataset.
          The CSV must contain boolean <code>is_malicious</code> column .
        </p>
      </div>


      <form onSubmit={handleTrain}>
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <div className="card-header">
            <h2 className="card-title">Upload Training Dataset</h2>
          </div>

          <div
            className={`csv-drop-zone${dragOver ? ' drag-over' : ''}${file ? ' has-file' : ''}`}
            onDragOver={e => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileRef.current?.click()}
            style={{ cursor: 'pointer' }}
          >
            <input
              ref={fileRef}
              type="file"
              accept=".csv"
              style={{ display: 'none' }}
              onChange={handleFileChange}
            />
            {file ? (
              <div className="drop-content">
                <div className="drop-label">{file.name}</div>
                <div className="drop-hint">
                  {(file.size / 1024).toFixed(1)} 
                </div>
              </div>
            ) : (
              <div className="drop-content">
                <div className="drop-label">Drag and drop CSV here or click to browse</div>
                <div className="drop-hint">Requires boolean <code>is_malicious</code> label column</div>
              </div>
            )}
          </div>

          {error && (
            <div className="error-banner" style={{ marginTop: '1rem' }}>
              {error}
            </div>
          )}

          <div style={{ marginTop: '1.25rem', display: 'flex', justifyContent: 'flex-end' }}>
            <button
              type="submit"
              className="btn-primary"
              disabled={training || !file}
              style={{ minWidth: 160 }}
            >
              {training ? (
                <span className="loading-dots">Training<span>.</span><span>.</span><span>.</span></span>
              ) : (
                'Train Model'
              )}
            </button>
          </div>
        </div>
      </form>

    
      {metrics && (
        <div className="metrics-section">
        
          <div className="result-header-card" style={{ marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
              <h2 style={{ margin: 0, color: 'var(--success)' }}>Training Complete</h2>
            </div>
            <p style={{ color: 'var(--text-muted)', margin: 0 }}>
              Trained on <strong style={{ color: 'var(--text)' }}>{metrics.training_records.toLocaleString()}</strong> records,
              evaluated on <strong style={{ color: 'var(--text)' }}>{metrics.test_records.toLocaleString()}</strong> held-out records.
              The model is now active.
            </p>
          </div>

        
          <div className="metrics-grid" style={{ marginBottom: '1.5rem' }}>
            {[
              { label: 'Accuracy',  value: pct(metrics.accuracy),  color: 'var(--gold)' },
              { label: 'Precision', value: pct(metrics.precision), color: 'var(--gold-light)' },
              { label: 'Recall',    value: pct(metrics.recall),    color: '#6ab4f5' },
              { label: 'F1-Score',  value: pct(metrics.f1),        color: 'var(--success)' },
            ].map(m => (
              <div key={m.label} className="metric-card">
                <div className="metric-value" style={{ color: m.color }}>{m.value}</div>
                <div className="metric-label">{m.label}</div>
              </div>
            ))}
          </div>

        
          <div className="card" style={{ marginBottom: '1.5rem' }}>
            <div className="card-header">
              <h2 className="card-title">Confusion Matrix</h2>
            </div>

            <div className="cm-container">
              <div className="cm-predicted-label">Predicted</div>
              <div className="cm-body">
                <div className="cm-actual-label">Actual</div>
                <div>
                  <div className="cm-col-headers">
                    <div className="cm-header-cell">Normal</div>
                    <div className="cm-header-cell">Malicious</div>
                  </div>
                  {['Normal', 'Malicious'].map((rowLabel, row) => (
                    <div key={row} className="cm-row">
                      <div className="cm-row-label">{rowLabel}</div>
                      {metrics.confusion_matrix[row].map((val, col) => {
                        const abbr = [[' TN', 'FP'], ['FN', ' TP']][row][col]
                        const desc = [['True Negative', 'False Positive'], ['False Negative', 'True Positive']][row][col]
                        return (
                          <div key={col} className="cm-cell" style={cmCellStyle(row, col, metrics.confusion_matrix)}>
                            <span className="cm-abbr">{abbr}</span>
                            <span className="cm-val">{val.toLocaleString()}</span>
                            <span className="cm-desc">{desc}</span>
                          </div>
                        )
                      })}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

      
          <div className="card">
            <div className="card-header">
              <h2 className="card-title">Classification Report</h2>
            </div>
            <pre className="metrics-report">{metrics.classification_report}</pre>
          </div>
        </div>
      )}
    </div>
  )
}
