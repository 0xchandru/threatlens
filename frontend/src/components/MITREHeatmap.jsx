const TACTICS_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
]

const CONF_COLOR = { high: '#DC2626', medium: '#EA580C', low: '#CA8A04' }

export default function MITREHeatmap({ techniques }) {
  if (!techniques?.length) return null

  const byTactic = {}
  for (const t of techniques) {
    if (!byTactic[t.tactic]) byTactic[t.tactic] = []
    byTactic[t.tactic].push(t)
  }

  const activeTactics = TACTICS_ORDER.filter(t => byTactic[t])

  return (
    <div className="rounded-xl border border-slate-700 p-4 bg-slate-900">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-slate-300">MITRE ATT&CK Mappings</h3>
        <span className="text-xs text-slate-500">{techniques.length} technique{techniques.length !== 1 ? 's' : ''}</span>
      </div>
      <div className="flex flex-wrap gap-2">
        {activeTactics.map(tactic => {
          const hits = byTactic[tactic]
          return (
            <div key={tactic}
              className="bg-slate-800 border border-slate-600 rounded-lg p-3 min-w-[150px]">
              <p className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                {tactic.replace(/-/g, ' ')}
              </p>
              {hits.map(t => (
                <div key={t.technique_id} className="mb-1.5">
                  <span className="font-mono text-xs font-bold" style={{ color: CONF_COLOR[t.confidence] }}>
                    {t.technique_id}
                  </span>
                  <p className="text-xs text-slate-300">{t.technique}</p>
                  <p className="text-xs text-slate-500 capitalize">{t.confidence} confidence · {t.source}</p>
                </div>
              ))}
            </div>
          )
        })}
      </div>
    </div>
  )
}
