import { getRiskConfig } from '../lib/scoring'

export default function ThreatScoreGauge({ score, riskLevel, confidence, queryTimeMs }) {
  const cfg = getRiskConfig(riskLevel)
  const pct = (score || 0) / 100

  return (
    <div className={`flex flex-col items-center p-6 rounded-2xl ${cfg.bg} border ${cfg.border}`}>
      <svg width="160" height="110" viewBox="0 0 160 110">
        <path d="M 20 90 A 60 60 0 0 1 140 90"
          fill="none" stroke="#1e293b" strokeWidth="14" strokeLinecap="round"/>
        <path d="M 20 90 A 60 60 0 0 1 140 90"
          fill="none" stroke={cfg.color} strokeWidth="14" strokeLinecap="round"
          strokeDasharray={`${188 * pct} 188`}
          style={{ transition: 'stroke-dasharray 0.8s ease' }}/>
        <text x="80" y="78" textAnchor="middle" fill="white"
          fontSize="32" fontWeight="700" fontFamily="monospace">
          {Math.round(score || 0)}
        </text>
        <text x="80" y="96" textAnchor="middle" fill="#94a3b8" fontSize="11">
          / 100
        </text>
      </svg>
      <span className="mt-1 text-lg font-semibold" style={{ color: cfg.color }}>
        {cfg.label}
      </span>
      <span className="text-xs text-slate-400 mt-1">
        Confidence: <span className="text-slate-300 capitalize">{confidence}</span>
      </span>
      {queryTimeMs != null && (
        <span className="text-xs text-slate-500 mt-1">
          {queryTimeMs}ms parallel
        </span>
      )}
    </div>
  )
}
