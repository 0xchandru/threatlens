export const RISK_CONFIG = {
  clean:      { color: '#00ff88', hex: '#00ff88', label: 'Clean',            glow: 'rgba(0,255,136,0.25)',   border: 'rgba(0,255,136,0.3)',   badgeBg: 'rgba(0,255,136,0.1)',   badgeText: '#00ff88',  ring: '#00ff88' },
  low:        { color: '#00d4ff', hex: '#00d4ff', label: 'Low Risk',         glow: 'rgba(0,212,255,0.2)',    border: 'rgba(0,212,255,0.3)',   badgeBg: 'rgba(0,212,255,0.1)',   badgeText: '#00d4ff',  ring: '#00d4ff' },
  suspicious: { color: '#ffaa00', hex: '#ffaa00', label: 'Suspicious',       glow: 'rgba(255,170,0,0.2)',    border: 'rgba(255,170,0,0.3)',   badgeBg: 'rgba(255,170,0,0.1)',   badgeText: '#ffaa00',  ring: '#ffaa00' },
  malicious:  { color: '#ff6b35', hex: '#ff6b35', label: 'Malicious',        glow: 'rgba(255,107,53,0.25)',  border: 'rgba(255,107,53,0.35)', badgeBg: 'rgba(255,107,53,0.1)',  badgeText: '#ff6b35',  ring: '#ff6b35' },
  critical:   { color: '#ff4444', hex: '#ff4444', label: 'Critical',         glow: 'rgba(255,68,68,0.3)',    border: 'rgba(255,68,68,0.4)',   badgeBg: 'rgba(255,68,68,0.12)',  badgeText: '#ff4444',  ring: '#ff4444' },
  unknown:    { color: '#8892a4', hex: '#8892a4', label: 'Unknown',          glow: 'rgba(136,146,164,0.1)',  border: 'rgba(136,146,164,0.2)', badgeBg: 'rgba(136,146,164,0.08)', badgeText: '#8892a4', ring: '#8892a4' },
}

export function getRiskConfig(riskLevel) {
  return RISK_CONFIG[riskLevel] || RISK_CONFIG.unknown
}

export function getRiskGradient(score) {
  if (score >= 80) return ['#ff4444', '#ff6b35']
  if (score >= 60) return ['#ff6b35', '#ffaa00']
  if (score >= 40) return ['#ffaa00', '#ffd700']
  if (score >= 20) return ['#00d4ff', '#0099bb']
  return ['#00ff88', '#00cc66']
}

