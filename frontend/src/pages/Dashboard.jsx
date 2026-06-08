import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import api from '../lib/api'
import ThreatTimeline from '../components/ThreatTimeline'
import { getRiskConfig } from '../lib/scoring'

const RISK_ORDER = ['critical', 'malicious', 'suspicious', 'low', 'clean']

function StatCard({ label, value, sub }) {
  return (
    <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
      <div className="text-2xl font-bold text-white">{value ?? '—'}</div>
      <div className="text-sm text-slate-400 mt-1">{label}</div>
      {sub && <div className="text-xs text-slate-500 mt-0.5">{sub}</div>}
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
  const pieData = RISK_ORDER
    .filter(r => riskDist[r])
    .map(r => ({ name: r, value: riskDist[r], color: getRiskConfig(r).color }))

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400 animate-pulse">Loading dashboard...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-slate-400 text-sm mt-1">Threat intelligence activity overview</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total IOCs" value={stats?.total_iocs?.toLocaleString()} />
        <StatCard label="Total Scans" value={stats?.total_scans?.toLocaleString()} />
        <StatCard label="Scans Today" value={stats?.scans_today?.toLocaleString()} />
        <StatCard label="Avg Query Time" value={stats?.avg_query_time_ms ? `${stats.avg_query_time_ms}ms` : '—'} sub="6 sources parallel" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Risk Distribution</h3>
          {pieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80}
                    dataKey="value" paddingAngle={3}>
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
                    formatter={(value, name) => [value, name.toUpperCase()]}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-wrap gap-2 justify-center mt-2">
                {pieData.map(item => (
                  <div key={item.name} className="flex items-center gap-1.5">
                    <div className="w-2.5 h-2.5 rounded-full" style={{ background: item.color }} />
                    <span className="text-xs text-slate-400 capitalize">{item.name} ({item.value})</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-40 text-slate-500 text-sm">
              No scan data yet
            </div>
          )}
        </div>

        <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-slate-300 mb-3">IOC Types</h3>
          {stats?.ioc_type_breakdown && Object.keys(stats.ioc_type_breakdown).length > 0 ? (
            <div className="space-y-2">
              {Object.entries(stats.ioc_type_breakdown).map(([type, count]) => {
                const max = Math.max(...Object.values(stats.ioc_type_breakdown))
                return (
                  <div key={type} className="flex items-center gap-2">
                    <span className="text-xs text-slate-400 font-mono w-16 uppercase">{type}</span>
                    <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-sky-500 rounded-full" style={{ width: `${(count/max)*100}%` }} />
                    </div>
                    <span className="text-xs text-slate-400 w-6 text-right">{count}</span>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="flex items-center justify-center h-40 text-slate-500 text-sm">No data yet</div>
          )}
        </div>

        <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-slate-300 mb-3">Top Tags</h3>
          {stats?.top_tags?.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {stats.top_tags.map(({ tag, count }) => (
                <span key={tag}
                  className="px-2 py-1 rounded-full bg-slate-700 text-slate-300 text-xs">
                  {tag} <span className="text-slate-500 ml-0.5">{count}</span>
                </span>
              ))}
            </div>
          ) : (
            <div className="flex items-center justify-center h-40 text-slate-500 text-sm">No tags yet</div>
          )}
        </div>
      </div>

      {timeline && <ThreatTimeline data={timeline} />}

      {stats?.recent_critical?.length > 0 && (
        <div className="bg-slate-900 border border-red-900 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-red-400 mb-3">⚠ Recent Critical IOCs</h3>
          <div className="space-y-2">
            {stats.recent_critical.map((item, i) => (
              <div key={i} className="flex items-center justify-between bg-slate-800 rounded-lg px-3 py-2">
                <span className="font-mono text-sm text-slate-200">{item.ioc_value}</span>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-slate-400 uppercase">{item.ioc_type}</span>
                  <span className="text-sm font-bold text-red-400">{item.composite_score?.toFixed(1)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {(!stats?.total_scans || stats.total_scans === 0) && (
        <div className="bg-slate-900 border border-slate-700 border-dashed rounded-xl p-8 text-center">
          <div className="text-4xl mb-3">🔍</div>
          <h3 className="text-lg font-semibold text-slate-300 mb-2">No investigations yet</h3>
          <p className="text-slate-500 text-sm mb-4">
            Start by looking up an IP, domain, URL, or file hash
          </p>
          <Link to="/lookup"
            className="inline-block px-6 py-2 bg-sky-600 hover:bg-sky-500 rounded-lg text-white text-sm font-medium transition-colors">
            Start Investigation
          </Link>
        </div>
      )}
    </div>
  )
}
