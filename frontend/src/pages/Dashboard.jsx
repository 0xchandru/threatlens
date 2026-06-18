import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts'
import api from '../lib/api'
import ThreatTimeline from '../components/ThreatTimeline'
import { getRiskConfig } from '../lib/scoring'

const RISK_ORDER = ['critical', 'malicious', 'suspicious', 'low', 'clean']

const card = { background: '#141b2d', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12 }

function KpiCard({ label, value, sub, color = '#00d4ff', icon, glow }) {
  return (
    <div style={{ ...card, padding: 20, position: 'relative', overflow: 'hidden', boxShadow: glow ? `0 0 20px ${glow}` : 'none' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontSize: 28, fontWeight: 800, color, fontFamily: 'monospace', lineHeight: 1 }}>{value ?? '—'}</div>
          <div style={{ fontSize: 12, color: '#8892a4', marginTop: 6 }}>{label}</div>
          {sub && <div style={{ fontSize: 10, color: '#8892a4', marginTop: 2, opacity: 0.7 }}>{sub}</div>}
        </div>
        {icon && <div style={{ fontSize: 24, opacity: 0.4 }}>{icon}</div>}
      </div>
      <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, ${color}, transparent)`, opacity: 0.4 }} />
    </div>
  )
}

function PieTooltip({ active, payload }) {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: '#141b2d', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 8, padding: '8px 14px' }}>
      <p style={{ color: payload[0]?.payload?.color, fontSize: 13, fontWeight: 700, textTransform: 'uppercase' }}>{payload[0]?.name}</p>
      <p style={{ color: '#c8d6e8', fontSize: 12 }}>{payload[0]?.value} IOCs</p>
    </div>
  )
}

export default function Dashboard() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => api.get('/dashboard/stats').then(r => r.data),
    refetchInterval: 30000,
  })

  const { data: timeline } = useQuery({
    queryKey: ['dashboard-timeline'],
    queryFn: () => api.get('/dashboard/timeline').then(r => r.data),
  })

  const riskDist = stats?.risk_distribution || {}
  const pieData  = RISK_ORDER.filter(r => riskDist[r]).map(r => ({
    name: r, value: riskDist[r], color: getRiskConfig(r).color,
  }))

  const typeBreakdown = stats?.ioc_type_breakdown || {}
  const typeMax = Math.max(...Object.values(typeBreakdown), 1)

  if (isLoading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="skeleton" style={{ height: 32, width: 200 }} />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 14 }}>
          {[1,2,3,4].map(i => <div key={i} className="skeleton" style={{ height: 90 }} />)}
        </div>
        <div className="skeleton" style={{ height: 220 }} />
      </div>
    )
  }

  const hasCritical = stats?.recent_critical?.length > 0
  const noData = !stats?.total_scans || stats.total_scans === 0

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#fff', margin: 0 }}>Dashboard</h1>
          <p style={{ color: '#8892a4', fontSize: 13, marginTop: 4 }}>Threat intelligence activity overview</p>
        </div>
        {hasCritical && (
          <div className="critical-pulse" style={{ padding: '6px 14px', borderRadius: 20, background: 'rgba(255,68,68,0.12)', border: '1px solid rgba(255,68,68,0.3)', color: '#ff4444', fontSize: 12, fontWeight: 700 }}>
            ● {stats.recent_critical.length} Critical IOC{stats.recent_critical.length !== 1 ? 's' : ''}
          </div>
        )}
      </div>

      {/* KPI Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 14 }}>
        <KpiCard label="Total IOCs" value={stats?.total_iocs?.toLocaleString()} icon="🗂" color="#00d4ff" />
        <KpiCard label="Total Scans" value={stats?.total_scans?.toLocaleString()} icon="📡" color="#7c3aed" />
        <KpiCard label="Scans Today" value={stats?.scans_today?.toLocaleString()} icon="📅" color="#00ff88" />
        <KpiCard label="Avg Query Time" value={stats?.avg_query_time_ms ? `${stats.avg_query_time_ms}ms` : '—'} sub="parallel" icon="⚡" color="#ffaa00" />
        <KpiCard label="Critical Threats" value={stats?.recent_critical?.length || 0} icon="🚨"
          color="#ff4444" glow={hasCritical ? 'rgba(255,68,68,0.2)' : undefined} />
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14 }}>
        {/* Risk Donut */}
        <div style={{ ...card, padding: 20 }}>
          <h3 style={{ fontSize: 12, fontWeight: 700, color: '#8892a4', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 12 }}>Risk Distribution</h3>
          {pieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={44} outerRadius={68} dataKey="value" paddingAngle={3}>
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                  <Tooltip content={<PieTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center', marginTop: 8 }}>
                {pieData.map(item => (
                  <div key={item.name} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: item.color }} />
                    <span style={{ fontSize: 10, color: '#8892a4', textTransform: 'capitalize' }}>{item.name} ({item.value})</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div style={{ height: 160, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#8892a4', fontSize: 13 }}>No scan data yet</div>
          )}
        </div>

        {/* IOC Types */}
        <div style={{ ...card, padding: 20 }}>
          <h3 style={{ fontSize: 12, fontWeight: 700, color: '#8892a4', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 12 }}>IOC Types</h3>
          {Object.keys(typeBreakdown).length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {Object.entries(typeBreakdown).map(([type, count]) => (
                <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: 10, fontFamily: 'monospace', fontWeight: 700, color: '#8892a4', width: 56, textTransform: 'uppercase' }}>{type}</span>
                  <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.05)', overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${(count / typeMax) * 100}%`, background: 'linear-gradient(90deg,#00d4ff,#0088cc)', borderRadius: 3, transition: 'width 0.8s ease' }} />
                  </div>
                  <span style={{ fontSize: 11, color: '#c8d6e8', width: 20, textAlign: 'right', fontFamily: 'monospace' }}>{count}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ height: 160, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#8892a4', fontSize: 13 }}>No data yet</div>
          )}
        </div>

        {/* Top Tags */}
        <div style={{ ...card, padding: 20 }}>
          <h3 style={{ fontSize: 12, fontWeight: 700, color: '#8892a4', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 12 }}>Top Tags</h3>
          {stats?.top_tags?.length > 0 ? (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
              {stats.top_tags.map(({ tag, count }) => (
                <span key={tag} style={{ padding: '4px 10px', borderRadius: 20, fontSize: 11, background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.18)', color: '#00d4ff', display: 'flex', alignItems: 'center', gap: 5 }}>
                  {tag}
                  <span style={{ fontSize: 10, color: '#8892a4' }}>{count}</span>
                </span>
              ))}
            </div>
          ) : (
            <div style={{ height: 160, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#8892a4', fontSize: 13 }}>No tags yet</div>
          )}
        </div>
      </div>

      {/* Timeline */}
      {timeline && <ThreatTimeline data={timeline} />}

      {/* Critical IOCs */}
      {hasCritical && (
        <div style={{ background: 'rgba(255,68,68,0.05)', border: '1px solid rgba(255,68,68,0.25)', borderRadius: 12, padding: 20 }}>
          <h3 style={{ fontSize: 12, fontWeight: 700, color: '#ff4444', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 12 }}>
            ⚠ Recent Critical IOCs
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {stats.recent_critical.map((item, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(255,68,68,0.06)', border: '1px solid rgba(255,68,68,0.15)', borderRadius: 8, padding: '10px 14px' }}>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: '#e2e8f0' }}>{item.ioc_value}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: 10, color: '#8892a4', textTransform: 'uppercase', fontWeight: 700 }}>{item.ioc_type}</span>
                  <span style={{ fontSize: 16, fontWeight: 800, color: '#ff4444', fontFamily: 'monospace' }}>{item.composite_score?.toFixed(0)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Empty state */}
      {noData && (
        <div style={{ ...card, padding: 60, textAlign: 'center', borderStyle: 'dashed' }}>
          <div style={{ fontSize: 52, marginBottom: 16, opacity: 0.3 }}>🔍</div>
          <h3 style={{ fontSize: 18, fontWeight: 700, color: '#c8d6e8', marginBottom: 8 }}>No investigations yet</h3>
          <p style={{ fontSize: 14, color: '#8892a4', marginBottom: 24 }}>
            Start by looking up an IP address, domain, URL, or file hash
          </p>
          <Link to="/lookup" style={{
            padding: '10px 28px', borderRadius: 10,
            background: 'linear-gradient(135deg, #00d4ff, #0088cc)',
            color: '#fff', fontSize: 14, fontWeight: 700, textDecoration: 'none',
            boxShadow: '0 0 20px rgba(0,212,255,0.3)',
          }}>
            Start First Investigation →
          </Link>
        </div>
      )}
    </div>
  )
}
