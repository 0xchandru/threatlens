import { useState, useEffect } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'

const IOC_PATTERNS = {
  ip:     /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F:]{2,}:{1,}).*$/,
  sha256: /^[a-fA-F0-9]{64}$/,
  sha1:   /^[a-fA-F0-9]{40}$/,
  md5:    /^[a-fA-F0-9]{32}$/,
  url:    /^https?:\/\//i,
  domain: /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/,
}

const PLACEHOLDERS = [
  'Enter an IP address…  e.g. 185.220.101.47',
  'Enter a domain…  e.g. malware-c2.net',
  'Enter a file hash (MD5 / SHA256)…',
  'Enter a URL…  e.g. https://phish.example.com/payload',
]

const TYPE_COLORS = {
  ip:     '#00d4ff',
  sha256: '#7c3aed',
  sha1:   '#7c3aed',
  md5:    '#7c3aed',
  url:    '#ffaa00',
  domain: '#00ff88',
}

function detectType(value) {
  const v = value.trim()
  for (const [type, pattern] of Object.entries(IOC_PATTERNS)) {
    if (pattern.test(v)) return type
  }
  return null
}

export default function IOCSearchBar({ onResult, initialValue = '' }) {
  const [input, setInput]         = useState(initialValue)
  const [detectedType, setType]   = useState(null)
  const [phIdx, setPhIdx]         = useState(0)
  const [focused, setFocused]     = useState(false)
  const queryClient               = useQueryClient()

  useEffect(() => {
    if (input) return
    const id = setInterval(() => setPhIdx(i => (i + 1) % PLACEHOLDERS.length), 3000)
    return () => clearInterval(id)
  }, [input])

  const lookupMutation = useMutation({
    mutationFn: (value) => api.post('/ioc/lookup', { value }),
    onSuccess: (data) => {
      onResult(data.data)
      queryClient.invalidateQueries(['dashboard-stats'])
    },
  })

  const handleInput = (e) => {
    const v = e.target.value
    setInput(v)
    setType(detectType(v))
  }

  const handleSubmit = () => {
    if (input.trim() && !lookupMutation.isPending) lookupMutation.mutate(input.trim())
  }

  const typeColor = detectedType ? TYPE_COLORS[detectedType] : null

  return (
    <div className="w-full">
      <div
        style={{
          border: `1px solid ${lookupMutation.isError ? '#ff4444' : focused ? 'rgba(0,212,255,0.5)' : 'rgba(255,255,255,0.08)'}`,
          background: '#0f1629',
          borderRadius: 14,
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          padding: '14px 16px',
          transition: 'border-color 0.2s, box-shadow 0.2s',
          boxShadow: focused ? '0 0 0 3px rgba(0,212,255,0.08)' : 'none',
        }}
      >
        <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke={focused ? '#00d4ff' : '#8892a4'} strokeWidth="2" style={{ flexShrink: 0, transition: 'stroke 0.2s' }}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>

        <input
          value={input}
          onChange={handleInput}
          onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          placeholder={PLACEHOLDERS[phIdx]}
          style={{
            flex: 1,
            background: 'transparent',
            color: '#e2e8f0',
            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
            fontSize: 14,
            outline: 'none',
            border: 'none',
          }}
        />

        {detectedType && (
          <span style={{
            padding: '3px 10px',
            borderRadius: 20,
            fontSize: 11,
            fontWeight: 600,
            fontFamily: 'monospace',
            background: `${typeColor}18`,
            border: `1px solid ${typeColor}40`,
            color: typeColor,
            flexShrink: 0,
            textTransform: 'uppercase',
          }}>
            {detectedType}
          </span>
        )}

        <button
          onClick={handleSubmit}
          disabled={!input.trim() || lookupMutation.isPending}
          style={{
            padding: '8px 20px',
            borderRadius: 10,
            background: lookupMutation.isPending ? 'rgba(0,212,255,0.2)' : 'linear-gradient(135deg, #00d4ff, #0088cc)',
            color: '#fff',
            fontSize: 13,
            fontWeight: 600,
            border: 'none',
            cursor: !input.trim() || lookupMutation.isPending ? 'not-allowed' : 'pointer',
            opacity: !input.trim() ? 0.4 : 1,
            flexShrink: 0,
            boxShadow: !input.trim() || lookupMutation.isPending ? 'none' : '0 0 16px rgba(0,212,255,0.3)',
            transition: 'all 0.2s',
          }}
        >
          {lookupMutation.isPending ? 'Querying…' : 'Analyze Threat'}
        </button>
      </div>

      {lookupMutation.isPending && (
        <div className="mt-3 flex items-center gap-2">
          <div style={{ width: 10, height: 10, borderRadius: '50%', border: '2px solid #00d4ff', borderTopColor: 'transparent', animation: 'spin 0.8s linear infinite' }} />
          <span style={{ fontSize: 12, color: '#8892a4' }}>
            Querying 6 threat intelligence sources in parallel…
          </span>
        </div>
      )}

      {lookupMutation.isError && (
        <div className="mt-3 flex items-center gap-2 px-3 py-2 rounded-lg" style={{ background: 'rgba(255,68,68,0.08)', border: '1px solid rgba(255,68,68,0.2)' }}>
          <span style={{ color: '#ff4444', fontSize: 12 }}>⚠ {lookupMutation.error?.message}</span>
        </div>
      )}
    </div>
  )
}
