import { getRiskConfig } from '../lib/scoring'

const ARC_LENGTH = 188

export default function ThreatScoreGauge({ score, riskLevel, confidence, queryTimeMs, size = 'lg' }) {
  const cfg = getRiskConfig(riskLevel)
  const pct = Math.min((score || 0) / 100, 1)
  const filled = ARC_LENGTH * pct
  const isCritical = riskLevel === 'critical'
  const isMd = size === 'md'
  const svgW = isMd ? 140 : 190
  const svgH = isMd ? 90 : 120
  const cx = svgW / 2
  const cy = isMd ? 80 : 105
  const r = isMd ? 52 : 72
  const sw = isMd ? 10 : 14

  const startAngle = Math.PI
  const endAngle = 0
  const x1 = cx + r * Math.cos(startAngle)
  const y1 = cy + r * Math.sin(startAngle)
  const x2 = cx + r * Math.cos(endAngle)
  const y2 = cy + r * Math.sin(endAngle)
  const d = `M ${x1} ${y1} A ${r} ${r} 0 0 1 ${x2} ${y2}`

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        padding: isMd ? '16px' : '24px',
        borderRadius: 16,
        background: `${cfg.color}0a`,
        border: `1px solid ${cfg.color}30`,
        boxShadow: isCritical ? `0 0 24px ${cfg.glow}` : `0 0 12px ${cfg.glow}`,
        position: 'relative',
      }}
      className={isCritical ? 'critical-pulse' : ''}
    >
      <svg width={svgW} height={svgH} viewBox={`0 0 ${svgW} ${svgH}`}>
        {/* Track */}
        <path d={d} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={sw} strokeLinecap="round" />
        {/* Filled arc */}
        <path
          d={d}
          fill="none"
          stroke={cfg.color}
          strokeWidth={sw}
          strokeLinecap="round"
          strokeDasharray={`${filled} ${ARC_LENGTH}`}
          className="gauge-arc"
          style={{ filter: `drop-shadow(0 0 6px ${cfg.color}80)` }}
        />
        {/* Score text */}
        <text x={cx} y={cy - (isMd ? 8 : 10)} textAnchor="middle" fill="white"
          fontSize={isMd ? 26 : 36} fontWeight="700" fontFamily="monospace">
          {Math.round(score || 0)}
        </text>
        <text x={cx} y={cy + (isMd ? 8 : 10)} textAnchor="middle" fill="#8892a4"
          fontSize={isMd ? 10 : 12}>
          / 100
        </text>
      </svg>

      <div style={{ marginTop: 4, fontSize: isMd ? 13 : 16, fontWeight: 700, color: cfg.color }}>
        {cfg.label}
        {isCritical && <span style={{ marginLeft: 6, fontSize: 12 }}>●</span>}
      </div>

      <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
        {confidence && (
          <span style={{ fontSize: 11, color: '#8892a4', textTransform: 'capitalize' }}>
            {confidence} confidence
          </span>
        )}
        {queryTimeMs != null && (
          <span style={{ fontSize: 11, color: '#8892a4' }}>{queryTimeMs}ms</span>
        )}
      </div>
    </div>
  )
}
