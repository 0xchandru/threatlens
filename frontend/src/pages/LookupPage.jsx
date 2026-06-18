import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import IOCSearchBar from '../components/IOCSearchBar'
import LookupResult from '../components/LookupResult'

const EXAMPLES = [
  { label: 'Malicious Tor IP',    value: '185.220.101.47',    type: 'ip' },
  { label: 'Clean domain',        value: 'google.com',         type: 'domain' },
  { label: 'EICAR test hash',     value: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', type: 'sha256' },
]

const SOURCE_CARDS = [
  { icon: '🔬', label: 'VirusTotal',     desc: '72 AV engines',       color: '#4285f4' },
  { icon: '🚨', label: 'AbuseIPDB',      desc: 'Abuse database',      color: '#ff6b35' },
  { icon: '👾', label: 'AlienVault OTX', desc: 'Threat pulses',       color: '#7c3aed' },
  { icon: '🔗', label: 'URLhaus',        desc: 'Malware URLs',        color: '#ff4444' },
  { icon: '🦊', label: 'ThreatFox',      desc: 'IOC sharing',         color: '#00d4ff' },
  { icon: '🧬', label: 'MalwareBazaar',  desc: 'Sample repository',   color: '#f472b6' },
]

export default function LookupPage() {
  const [result, setResult]       = useState(null)
  const [searchParams]            = useSearchParams()
  const [prefilledQ]              = useState(searchParams.get('q') || '')

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#fff', margin: 0 }}>IOC Lookup</h1>
        <p style={{ color: '#8892a4', fontSize: 13, marginTop: 4 }}>
          Analyze any indicator across 6 threat intelligence sources in parallel
        </p>
      </div>

      {/* Search hero */}
      <div style={{ background: '#141b2d', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 14, padding: 28 }}>
        <IOCSearchBar onResult={setResult} initialValue={prefilledQ} />

        {/* Source capabilities */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(140px,1fr))', gap: 10, marginTop: 20 }}>
          {SOURCE_CARDS.map(src => (
            <div key={src.label} style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '10px 12px', borderRadius: 10,
              background: `${src.color}08`, border: `1px solid ${src.color}20`,
            }}>
              <span style={{ fontSize: 20 }}>{src.icon}</span>
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, color: src.color }}>{src.label}</div>
                <div style={{ fontSize: 10, color: '#8892a4' }}>{src.desc}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Example pills */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 16, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: '#8892a4' }}>Try:</span>
          {EXAMPLES.map(ex => (
            <button key={ex.value}
              onClick={() => {
                const event = new CustomEvent('threatlens:prefill', { detail: ex.value })
                window.dispatchEvent(event)
                navigator.clipboard?.writeText(ex.value)
              }}
              style={{
                padding: '3px 12px', borderRadius: 20, fontSize: 11, cursor: 'pointer',
                background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
                color: '#8892a4', transition: 'all 0.15s',
              }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(0,212,255,0.08)'; e.currentTarget.style.color = '#00d4ff' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.04)'; e.currentTarget.style.color = '#8892a4' }}
            >
              {ex.label}
            </button>
          ))}
        </div>
      </div>

      {/* Empty state */}
      {!result && (
        <div style={{ textAlign: 'center', padding: '32px 0', color: '#8892a4' }}>
          <div style={{ fontSize: 52, marginBottom: 12, opacity: 0.3 }}>🔍</div>
          <p style={{ fontSize: 14, color: '#8892a4' }}>Enter an IP, domain, URL, or file hash above to begin analysis</p>
        </div>
      )}

      {/* Results */}
      {result && (
        <LookupResult result={result} onClose={() => setResult(null)} />
      )}
    </div>
  )
}
