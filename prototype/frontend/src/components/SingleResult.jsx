export const FEATURE_LABELS = {
  employee_seniority_years:     'Seniority (Years)',
  total_files_burned:           'Total Files Burned',
  burned_from_other:            'Files Burned (Other Source)',
  num_printed_pages_off_hours:  'Off-Hours Print Pages',
  total_printed_pages:          'Total Print Pages',
  num_entries:                  'Building Entries',
  late_exit_flag:               'Late Exit Count',
  entry_during_weekend:         'Weekend Entries',
  trip_day_number:              'Trip Duration (Days)',
  hostility_country_level:      'Travel Country Risk',
  has_criminal_record:          'Criminal Record on File',

  employee_department:          'Department',
  employee_classification:      'Classification',
  is_contractor:                'Contractor',
}

function ExplanationBlock({ text }) {
  if (!text) return null
  const parts = text.split('\n\n')
  return (
    <div>
      {parts.map((part, i) => (
        <p
          key={i}
          style={{
            fontSize: '0.875rem',
            color: 'var(--text-muted)',
            lineHeight: 1.75,
            marginBottom: i < parts.length - 1 ? '0.85rem' : 0,
            whiteSpace: 'pre-wrap',
          }}
        >
          {part}
        </p>
      ))}
    </div>
  )
}

function threatColor(pct) {
  if (pct >= 65) return 'var(--danger)'
  if (pct >= 45) return 'var(--warning)'
  if (pct >= 40) return 'var(--caution)'
  return 'var(--success)'
}

function threatLabel(pct) {
  if (pct >= 65) return 'Malicious'
  if (pct >= 45) return 'Suspicious'
  if (pct >= 40) return 'Borderline'
  return 'Not-suspicious'
}

function threatClass(pct) {
  if (pct >= 65) return 'malicious'
  if (pct >= 45) return 'suspicious'
  if (pct >= 40) return 'borderline'
  return 'normal'
}


export default function SingleResult({ result, onBack, backLabel = '← Back to Analysis' }) {
  const pct         = result.confidence_pct ?? Math.round(result.probability * 100)
  const color       = threatColor(pct)
  const label       = threatLabel(pct)
  const tClass      = threatClass(pct)
  const indicators  = result.risk_indicators ?? []
  const importances = result.global_feature_importance ?? []
  const explanation = result.manager_explanation ?? ''

  return (
    <div>
     
      {(onBack || result.profile_name) && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
          {onBack && (
            <button className="btn btn-secondary" onClick={onBack}>
              {backLabel}
            </button>
          )}
          {result.profile_name && (
            <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
              Profile: <strong style={{ color: 'var(--gold)' }}>{result.profile_name}</strong>
              {' '}—{' '}{result.profile_title}
            </span>
          )}
        </div>
      )}

      {result.demo_mode && (
        <div className="alert alert-info" style={{ marginBottom: '1.25rem' }}>
          <span>Running in <strong>DEMO MODE</strong> model not trained.</span>
        </div>
      )}

      <div className="result-layout">

      
        <div className={`verdict-card verdict-${tClass}`}>
          <div className="verdict-body">
            <div className="verdict-label">{label}</div>
            <div className="verdict-title">
              {tClass === 'malicious'   && 'MALICIOUS INSIDER ACTIVITY DETECTED'}
              {tClass === 'suspicious'  && 'SUSPICIOUS ACTIVITY — REVIEW RECOMMENDED'}
              {tClass === 'borderline'  && 'BORDERLINE ACTIVITY — MONITOR CLOSELY'}
              {tClass === 'normal'      && 'NORMAL EMPLOYEE BEHAVIOUR'}
            </div>
            <div className="verdict-subtitle">
              {tClass === 'malicious'  && 'Elevated risk indicators identified. Recommend immediate security review.'}
              {tClass === 'suspicious' && 'Multiple elevated indicators detected. Warrants further investigation.'}
              {tClass === 'borderline' && 'Some unusual patterns present. Routine monitoring advised.'}
              {tClass === 'normal'     && 'Activity patterns are consistent with normal behaviour.'}
            </div>
            <div className="confidence-section">
              <div className="confidence-row">
                <span className="conf-label">Threat Score</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{
                    fontSize: '0.65rem', fontWeight: 700, textTransform: 'uppercase',
                    letterSpacing: '0.06em', background: `${color}33`, color,
                    padding: '0.15rem 0.5rem', borderRadius: '99px',
                  }}>
                    {label}
                  </span>
                  <span className="conf-pct" style={{ color }}>{pct}%</span>
                </div>
              </div>
              <div className="conf-bar-bg">
                <div className="conf-bar-fill" style={{ width: `${pct}%`, background: color }} />
              </div>
            </div>
          </div>
        </div>

      
        <div className="card">
          <div className="card-title">
            Risk Indicators
            {indicators.length > 0 && (
              <span style={{ marginLeft: '0.5rem', color: 'var(--text-dim)' }}>
                ({result.high_risk_count ?? 0} high · {result.medium_risk_count ?? 0} medium · {result.low_risk_count ?? 0} low)
              </span>
            )}
          </div>
          {indicators.length === 0 ? (
            <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
              No significant risk indicators detected.
            </p>
          ) : (
            <div className="risk-list">
              {indicators.map((ind, i) => (
                <div key={i} className={`risk-item risk-${ind.risk_level}`}>
                  <span className="risk-chip">{ind.risk_level}</span>
                  <div>
                    <div className="risk-feature-name">
                      {FEATURE_LABELS[ind.feature] ?? ind.label ?? ind.feature}
                    </div>
                    <div className="risk-explanation">{ind.explanation}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

      
        {explanation && (
          <div className="card">
            <div className="card-title">Manager Briefing</div>
            <ExplanationBlock text={explanation} />
          </div>
        )}

      
        {result.record && (
          <div className="card">
            <div className="card-title">Input Data</div>
            <div className="data-summary-grid">
              {Object.entries(result.record)
                .filter(([k]) => FEATURE_LABELS[k])
                .map(([k, v]) => (
                  <div key={k} className="data-row">
                    <span className="data-key">{FEATURE_LABELS[k]}</span>
                    <span className="data-value">
                      {k === 'is_contractor' ? (v ? 'Yes' : 'No') : String(v)}
                    </span>
                  </div>
                ))}
            </div>
          </div>
        )}

       
        {importances.length > 0 && (
          <div className="card">
            <div className="card-title">Feature Importance (Global)</div>
            <div className="importance-list">
              {importances.slice(0, 12).map((f, i) => (
                <div key={i}>
                  <div className="imp-row">
                    <span className="imp-name">{FEATURE_LABELS[f.feature] ?? f.label ?? f.feature}</span>
                    <span className="imp-pct">{f.importance.toFixed(1)}%</span>
                  </div>
                  <div className="imp-bg">
                    <div className="imp-fill" style={{ width: `${f.bar_width ?? f.importance}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
  )
}
