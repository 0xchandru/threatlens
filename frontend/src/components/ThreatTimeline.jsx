import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: '#141b2d', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 8, padding: '8px 14px' }}>
      <p style={{ color: '#8892a4', fontSize: 11, marginBottom: 4 }}>{label}</p>
      <p style={{ color: '#00d4ff', fontSize: 14, fontWeight: 700 }}>{payload[0]?.value} scans</p>
    </div>
  )
}

export default function ThreatTimeline({ data }) {
  if (!data?.length) return null

  return (
    <div style={{ background: '#141b2d', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: 20 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h3 style={{ fontSize: 13, fontWeight: 600, color: '#c8d6e8', margin: 0 }}>Scan Activity — 30 Days</h3>
        <span style={{ fontSize: 11, color: '#8892a4' }}>{data.reduce((a, d) => a + (d.count || 0), 0)} total scans</span>
      </div>
      <ResponsiveContainer width="100%" height={150}>
        <AreaChart data={data} margin={{ top: 5, right: 5, bottom: 0, left: -25 }}>
          <defs>
            <linearGradient id="tl_grad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="#00d4ff" stopOpacity={0.25} />
              <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
          <XAxis dataKey="date" tick={{ fill: '#8892a4', fontSize: 10 }} tickLine={false} axisLine={false} />
          <YAxis tick={{ fill: '#8892a4', fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
          <Tooltip content={<CustomTooltip />} />
          <Area type="monotone" dataKey="count" stroke="#00d4ff" strokeWidth={2}
            fill="url(#tl_grad)" name="Scans" dot={false} activeDot={{ r: 4, fill: '#00d4ff', stroke: '#0a0e1a', strokeWidth: 2 }} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
