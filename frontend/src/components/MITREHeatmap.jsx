const TACTICS_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
]

const CONF_CONFIG = {
  high:   { color: '#ff4444', label: 'High' },
  medium: { color: '#ffaa00', label: 'Med' },
  low:    { color: '#8892a4', label: 'Low' },
}

export default function MITREHeatmap({ techniques }) {
  if (!techniques?.length) return null

  const byTactic = {}
  for (const t of techniques) {
    const key = (t.tactic || '').toLowerCase()
    if (!byTactic[key]) byTactic[key] = []
    byTactic[key].push(t)
  }
  const activeTactics = TACTICS_ORDER.filter(t => byTactic[t])

  return (
    <div style={{ background: 'rgba(124,58,237,0.05)', border: '1px solid rgba(124,58,237,0.2)', borderRadius: 12, padding: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 8, background: 'rgba(124,58,237,0.2)', border: '1px solid rgba(124,58,237,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="#7c3aed" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
            </svg>
          </div>
          <div>
            <h3 style={{ fontSize: 13, fontWeight: 700, color: '#c8d6e8', margin: 0 }}>MITRE ATT&CK Mappings</h3>
            <p style={{ fontSize: 11, color: '#8892a4', margin: 0 }}>{techniques.length} technique{techniques.length !== 1 ? 's' : ''} mapped</p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {Object.entries(CONF_CONFIG).map(([k, v]) => (
            <span key={k} style={{ fontSize: 10, color: v.color, display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: v.color, display: 'inline-block' }} />
              {v.label}
            </span>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
        {activeTactics.map(tactic => {
          const hits = byTactic[tactic]
          return (
            <div key={tactic} style={{
              background: 'rgba(124,58,237,0.08)',
              border: '1px solid rgba(124,58,237,0.15)',
              borderRadius: 10,
              padding: 12,
              minWidth: 160,
            }}>
              <p style={{ fontSize: 9, fontWeight: 700, color: '#7c3aed', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10 }}>
                {tactic.replace(/-/g, ' ')}
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {hits.map(t => {
                  const conf = CONF_CONFIG[t.confidence] || CONF_CONFIG.low
                  return (
                    <div key={t.technique_id} style={{ borderLeft: `2px solid ${conf.color}`, paddingLeft: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                        <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 700, color: conf.color }}>{t.technique_id}</span>
                        <span style={{ fontSize: 9, color: conf.color, background: `${conf.color}18`, padding: '1px 5px', borderRadius: 4 }}>{conf.label}</span>
                      </div>
                      <p style={{ fontSize: 11, color: '#c8d6e8', margin: 0 }}>{t.technique}</p>
                      <p style={{ fontSize: 10, color: '#8892a4', margin: '2px 0 0' }}>via {t.source}</p>
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
