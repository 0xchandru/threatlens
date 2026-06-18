import { useState } from 'react'
import ThreatScoreGauge from './ThreatScoreGauge'
import SourceResultCard from './SourceResultCard'
import MITREHeatmap from './MITREHeatmap'
import AnalystPanel from './AnalystPanel'
import { useMutation } from '@tanstack/react-query'
import { getRiskConfig } from '../lib/scoring'
import api from '../lib/api'

const SOURCES = ['virustotal', 'abuseipdb', 'alienvault', 'urlhaus', 'threatfox', 'malwarebazaar']
const WEIGHTS  = { virustotal: 30, abuseipdb: 23, alienvault: 20, urlhaus: 11, threatfox: 10, malwarebazaar: 6 }

function copyToClipboard(text) {
  navigator.clipboard?.writeText(text).catch(() => {})
}

function SectionHeader({ title, subtitle, color = '#00d4ff', icon }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
      {icon && (
        <div style={{ width: 26, height: 26, borderRadius: 7, background: `${color}18`, border: `1px solid ${color}35`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          {icon}
        </div>
      )}
      <div>
        <h3 style={{ fontSize: 13, fontWeight: 700, color: '#c8d6e8', margin: 0 }}>{title}</h3>
        {subtitle && <p style={{ fontSize: 11, color: '#8892a4', margin: 0 }}>{subtitle}</p>}
      </div>
    </div>
  )
}

export default function LookupResult({ result, onClose }) {
  const [copied, setCopied] = useState(false)
  if (!result) return null

  const { ioc, score, risk_level, confidence, breakdown, mitre, results, errors, query_time_ms, notes, tags, source } = result
  const cfg = getRiskConfig(risk_level)

  const generateReport = useMutation({
    mutationFn: () => api.post('/reports/generate', { ioc_value: ioc.value, scan_id: result.scan_id }),
    onSuccess: (res) => window.open(`/api/v1/reports/${res.data.id}/download`, '_blank'),
  })

  const handleCopy = () => {
    copyToClipboard(ioc?.value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }} className="fade-up">

      {/* Hero summary card */}
      <div style={{
        background: '#141b2d',
        border: `1px solid ${cfg.color}30`,
        borderRadius: 14,
        padding: 24,
        boxShadow: `0 0 40px ${cfg.glow}`,
      }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
          {/* Left: IOC info + gauge */}
          <div style={{ display: 'flex', gap: 24, alignItems: 'flex-start', flex: 1, minWidth: 0 }}>
            <ThreatScoreGauge score={score} riskLevel={risk_level} confidence={confidence} queryTimeMs={query_time_ms} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6, flexWrap: 'wrap' }}>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 16, fontWeight: 700, color: '#fff', wordBreak: 'break-all' }}>
                  {ioc?.value}
                </span>
                <button onClick={handleCopy} title="Copy to clipboard"
                  style={{ background: 'rgba(255,255,255,0.06)', border: 'none', borderRadius: 6, padding: '3px 8px', cursor: 'pointer', color: copied ? '#00ff88' : '#8892a4', fontSize: 11 }}>
                  {copied ? '✓ Copied' : '⎘ Copy'}
                </button>
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 14 }}>
                <span style={{ padding: '3px 10px', borderRadius: 6, fontSize: 11, fontWeight: 700, background: 'rgba(255,255,255,0.06)', color: '#8892a4', textTransform: 'uppercase', fontFamily: 'monospace' }}>
                  {ioc?.type}
                </span>
                <span style={{ padding: '3px 12px', borderRadius: 20, fontSize: 11, fontWeight: 700, background: cfg.badgeBg, color: cfg.badgeText, border: `1px solid ${cfg.border}`, textTransform: 'uppercase' }}
                  className={risk_level === 'critical' ? 'critical-pulse' : ''}>
                  {cfg.label}
                </span>
                {source === 'cache' && (
                  <span style={{ padding: '3px 10px', borderRadius: 6, fontSize: 11, background: 'rgba(255,170,0,0.08)', color: '#ffaa00', border: '1px solid rgba(255,170,0,0.2)' }}>
                    ⚡ Cached
                  </span>
                )}
                <span style={{ padding: '3px 10px', borderRadius: 6, fontSize: 11, color: '#8892a4', background: 'rgba(255,255,255,0.04)' }}>
                  {query_time_ms}ms · {SOURCES.length} sources
                </span>
              </div>

              {/* Score breakdown */}
              {breakdown && Object.keys(breakdown).length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                  {Object.entries(breakdown).filter(([,v]) => v > 0).map(([src, val]) => {
                    const maxW = WEIGHTS[src] || 10
                    const pct = Math.min((val / maxW) * 100, 100)
                    return (
                      <div key={src} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 10, color: '#8892a4', width: 90, textTransform: 'capitalize', fontWeight: 500 }}>{src}</span>
                        <div style={{ flex: 1, height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
                          <div style={{ height: '100%', width: `${pct}%`, background: pct > 60 ? '#ff4444' : pct > 30 ? '#ffaa00' : '#00d4ff', borderRadius: 2, transition: 'width 0.8s ease' }} />
                        </div>
                        <span style={{ fontSize: 10, color: '#c8d6e8', width: 28, textAlign: 'right', fontFamily: 'monospace' }}>{val}</span>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          </div>

          {/* Right: actions */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, flexShrink: 0 }}>
            <button onClick={() => generateReport.mutate()} disabled={generateReport.isPending}
              style={{ padding: '8px 18px', borderRadius: 8, background: 'linear-gradient(135deg,#00d4ff,#0088cc)', color: '#fff', fontSize: 12, fontWeight: 700, border: 'none', cursor: generateReport.isPending ? 'wait' : 'pointer', boxShadow: '0 0 14px rgba(0,212,255,0.25)', opacity: generateReport.isPending ? 0.7 : 1 }}>
              {generateReport.isPending ? 'Generating…' : '📄 PDF Report'}
            </button>
            <button onClick={onClose}
              style={{ padding: '8px 18px', borderRadius: 8, background: 'rgba(255,255,255,0.04)', color: '#8892a4', fontSize: 12, fontWeight: 600, border: '1px solid rgba(255,255,255,0.08)', cursor: 'pointer' }}>
              ✕ Clear
            </button>
          </div>
        </div>
      </div>

      {/* Error banner */}
      {errors?.length > 0 && (
        <div style={{ background: 'rgba(255,170,0,0.06)', border: '1px solid rgba(255,170,0,0.2)', borderRadius: 10, padding: '12px 16px' }}>
          <p style={{ fontSize: 11, color: '#ffaa00', fontWeight: 700, marginBottom: 6 }}>⚠ Partial Results — Some Sources Failed</p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {errors.map((e, i) => (
              <span key={i} style={{ fontSize: 10, color: '#c8a000', background: 'rgba(255,170,0,0.08)', padding: '2px 8px', borderRadius: 6 }}>
                {e.source}: {e.error}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Source results */}
      <div style={{ background: '#141b2d', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: 20 }}>
        <SectionHeader
          title="Intelligence Sources"
          subtitle={`${SOURCES.filter(s => results?.[s]?.status === 'found').length} sources flagged this IOC`}
          icon={<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="#00d4ff" strokeWidth="2"><path strokeLinecap="round" strokeLinejoin="round" d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" /></svg>}
        />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 12 }}>
          {SOURCES.map(src => (
            <SourceResultCard key={src} source={src} data={results?.[src]} />
          ))}
        </div>
      </div>

      {/* MITRE */}
      {mitre?.length > 0 && <MITREHeatmap techniques={mitre} />}

      {/* Analyst workspace */}
      <div style={{ background: '#141b2d', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: 20 }}>
        <SectionHeader
          title="Analyst Workspace"
          subtitle="Add notes and tags to this investigation"
          icon={<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="#00d4ff" strokeWidth="2"><path strokeLinecap="round" strokeLinejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>}
        />
        <AnalystPanel iocValue={ioc?.value} notes={notes || []} tags={tags || []} />
      </div>
    </div>
  )
}
