import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import api from '../lib/api'
import { getRiskConfig } from '../lib/scoring'

const RISK_LEVELS = ['', 'critical', 'malicious', 'suspicious', 'low', 'clean']
const IOC_TYPES   = ['', 'ip', 'domain', 'url', 'md5', 'sha1', 'sha256']

const S = {
  card:  { background: '#141b2d', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: 20 },
  input: { background: '#0f1629', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, padding: '8px 12px', fontSize: 13, color: '#e2e8f0', outline: 'none', fontFamily: 'inherit' },
  sel:   { background: '#0f1629', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, padding: '8px 12px', fontSize: 13, color: '#e2e8f0', outline: 'none', fontFamily: 'inherit', cursor: 'pointer' },
}

function RiskBadge({ level }) {
  if (!level) return null
  const cfg = getRiskConfig(level)
  return (
    <span style={{ padding: '2px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700,
      background: cfg.badgeBg, color: cfg.badgeText, border: `1px solid ${cfg.border}`, textTransform: 'uppercase' }}>
      {cfg.label}
    </span>
  )
}

export default function SearchPage() {
  const navigate = useNavigate()
  const [tag,       setTag]       = useState('')
  const [riskLevel, setRiskLevel] = useState('')
  const [iocType,   setIocType]   = useState('')
  const [submitted, setSubmitted] = useState(false)

  const { data: results, isFetching } = useQuery({
    queryKey: ['search', tag, riskLevel, iocType],
    queryFn: () => {
      const params = new URLSearchParams()
      if (tag)       params.append('tag',        tag)
      if (riskLevel) params.append('risk_level', riskLevel)
      if (iocType)   params.append('ioc_type',   iocType)
      return api.get(`/search?${params}`).then(r => r.data)
    },
    enabled: submitted,
  })

  const handleSearch = (e) => {
    e.preventDefault()
    setSubmitted(true)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#fff', margin: 0 }}>Threat Hunt</h1>
        <p style={{ color: '#8892a4', fontSize: 13, marginTop: 4 }}>Filter and search through all investigated indicators</p>
      </div>

      {/* Filters */}
      <form onSubmit={handleSearch} style={{ ...S.card, display: 'flex', flexWrap: 'wrap', gap: 16, alignItems: 'flex-end' }}>
        <div style={{ flex: '1 1 200px' }}>
          <label style={{ fontSize: 11, color: '#8892a4', display: 'block', marginBottom: 6, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Tag</label>
          <input value={tag} onChange={e => setTag(e.target.value)} placeholder="e.g. c2, ransomware" style={{ ...S.input, width: '100%' }} />
        </div>
        <div style={{ flex: '0 0 160px' }}>
          <label style={{ fontSize: 11, color: '#8892a4', display: 'block', marginBottom: 6, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Risk Level</label>
          <select value={riskLevel} onChange={e => setRiskLevel(e.target.value)} style={{ ...S.sel, width: '100%' }}>
            {RISK_LEVELS.map(r => <option key={r} value={r}>{r || 'All Levels'}</option>)}
          </select>
        </div>
        <div style={{ flex: '0 0 140px' }}>
          <label style={{ fontSize: 11, color: '#8892a4', display: 'block', marginBottom: 6, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>IOC Type</label>
          <select value={iocType} onChange={e => setIocType(e.target.value)} style={{ ...S.sel, width: '100%' }}>
            {IOC_TYPES.map(t => <option key={t} value={t}>{t || 'All Types'}</option>)}
          </select>
        </div>
        <button type="submit" style={{
          padding: '9px 24px', borderRadius: 8, background: 'linear-gradient(135deg,#00d4ff,#0088cc)',
          color: '#fff', fontSize: 13, fontWeight: 700, border: 'none', cursor: 'pointer',
          boxShadow: '0 0 16px rgba(0,212,255,0.25)',
        }}>
          Search
        </button>
      </form>

      {/* Loading */}
      {isFetching && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#8892a4', fontSize: 13 }}>
          <div style={{ width: 14, height: 14, borderRadius: '50%', border: '2px solid #00d4ff', borderTopColor: 'transparent', animation: 'spin 0.8s linear infinite' }} />
          Searching…
        </div>
      )}

      {/* Results */}
      {results && (
        <div>
          <p style={{ fontSize: 12, color: '#8892a4', marginBottom: 12 }}>
            {results.length} result{results.length !== 1 ? 's' : ''}
          </p>
          {results.length === 0 ? (
            <div style={{ ...S.card, textAlign: 'center', padding: 48 }}>
              <div style={{ fontSize: 40, marginBottom: 12 }}>🔍</div>
              <p style={{ color: '#8892a4', fontSize: 14 }}>No IOCs found matching your filters</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {results.map(ioc => (
                <div key={ioc.id} style={{
                  ...S.card, padding: '14px 20px',
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  cursor: 'pointer', transition: 'border-color 0.15s',
                }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = 'rgba(0,212,255,0.2)'}
                  onMouseLeave={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'}
                >
                  <div>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: '#e2e8f0' }}>{ioc.value}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 5 }}>
                      <span style={{ padding: '1px 8px', borderRadius: 4, background: 'rgba(255,255,255,0.06)', color: '#8892a4', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', fontFamily: 'monospace' }}>
                        {ioc.ioc_type}
                      </span>
                      <span style={{ fontSize: 11, color: '#8892a4' }}>{ioc.lookup_count} lookup{ioc.lookup_count !== 1 ? 's' : ''}</span>
                      {ioc.last_seen && <span style={{ fontSize: 11, color: '#8892a4' }}>Last: {new Date(ioc.last_seen).toLocaleDateString()}</span>}
                    </div>
                  </div>
                  <button
                    onClick={() => navigate(`/lookup?q=${encodeURIComponent(ioc.value)}`)}
                    style={{ padding: '6px 16px', borderRadius: 8, background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', color: '#00d4ff', fontSize: 12, fontWeight: 600, cursor: 'pointer' }}
                  >
                    Analyze →
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!submitted && !isFetching && (
        <div style={{ textAlign: 'center', padding: '60px 0', color: '#8892a4' }}>
          <div style={{ fontSize: 40, marginBottom: 12, opacity: 0.4 }}>🛡</div>
          <p style={{ fontSize: 14 }}>Use the filters above to search your investigated IOCs</p>
        </div>
      )}
    </div>
  )
}
