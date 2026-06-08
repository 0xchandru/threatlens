export const RISK_CONFIG = {
  clean:      { color: '#16A34A', label: 'Clean',      bg: 'bg-green-900/30',  border: 'border-green-700',  badge: 'bg-green-900 text-green-300' },
  low:        { color: '#2563EB', label: 'Low Risk',   bg: 'bg-blue-900/30',   border: 'border-blue-700',   badge: 'bg-blue-900 text-blue-300' },
  suspicious: { color: '#CA8A04', label: 'Suspicious', bg: 'bg-yellow-900/30', border: 'border-yellow-700', badge: 'bg-yellow-900 text-yellow-300' },
  malicious:  { color: '#EA580C', label: 'Malicious',  bg: 'bg-orange-900/30', border: 'border-orange-700', badge: 'bg-orange-900 text-orange-300' },
  critical:   { color: '#DC2626', label: 'Critical',   bg: 'bg-red-900/30',    border: 'border-red-700',    badge: 'bg-red-900 text-red-300' },
}

export function getRiskConfig(riskLevel) {
  return RISK_CONFIG[riskLevel] || RISK_CONFIG.clean
}
