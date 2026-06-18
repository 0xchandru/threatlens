import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import api from '../lib/api'

const S = {
  card: { background: '#141b2d', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12 },
}

export default function ReportsPage() {
  const { data: reports, isLoading } = useQuery({
    queryKey: ['reports'],
    queryFn: () => api.get('/reports').then(r => r.data),
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#fff', margin: 0 }}>Reports</h1>
          <p style={{ color: '#8892a4', fontSize: 13, marginTop: 4 }}>
            PDF threat intelligence reports — generated from IOC lookups
          </p>
        </div>
        <Link to="/lookup" style={{
          padding: '8px 18px', borderRadius: 8,
          background: 'linear-gradient(135deg,#00d4ff,#0088cc)',
          color: '#fff', fontSize: 13, fontWeight: 700, textDecoration: 'none',
          boxShadow: '0 0 16px rgba(0,212,255,0.25)',
        }}>
          + New Lookup
        </Link>
      </div>

      {/* Loading */}
      {isLoading && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[1,2,3].map(i => (
            <div key={i} className="skeleton" style={{ height: 64, borderRadius: 12 }} />
          ))}
        </div>
      )}

      {/* Empty state */}
      {!isLoading && reports?.length === 0 && (
        <div style={{ ...S.card, padding: 60, textAlign: 'center', borderStyle: 'dashed' }}>
          <div style={{ fontSize: 48, marginBottom: 16, opacity: 0.5 }}>📋</div>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: '#c8d6e8', marginBottom: 8 }}>No reports yet</h3>
          <p style={{ fontSize: 13, color: '#8892a4', marginBottom: 20 }}>
            Run an IOC lookup and click "PDF Report" to generate a professional report
          </p>
          <Link to="/lookup" style={{
            padding: '9px 22px', borderRadius: 8, background: 'rgba(0,212,255,0.12)',
            border: '1px solid rgba(0,212,255,0.25)', color: '#00d4ff',
            fontSize: 13, fontWeight: 600, textDecoration: 'none',
          }}>
            Start Investigation →
          </Link>
        </div>
      )}

      {/* Reports list */}
      {reports?.length > 0 && (
        <div>
          <p style={{ fontSize: 12, color: '#8892a4', marginBottom: 12 }}>{reports.length} report{reports.length !== 1 ? 's' : ''}</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {reports.map((report, i) => (
              <div key={report.id} style={{
                ...S.card, padding: '14px 20px',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                transition: 'border-color 0.15s',
              }}
                onMouseEnter={e => e.currentTarget.style.borderColor = 'rgba(0,212,255,0.15)'}
                onMouseLeave={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                  <div style={{ width: 36, height: 36, borderRadius: 8, background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16 }}>
                    📄
                  </div>
                  <div>
                    <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#e2e8f0' }}>{report.filename}</div>
                    <div style={{ fontSize: 11, color: '#8892a4', marginTop: 3 }}>
                      {report.created_at ? new Date(report.created_at).toLocaleString() : '—'}
                    </div>
                  </div>
                </div>
                <a
                  href={`/api/v1/reports/${report.id}/download`}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    padding: '7px 16px', borderRadius: 8,
                    background: 'rgba(0,212,255,0.12)',
                    border: '1px solid rgba(0,212,255,0.2)',
                    color: '#00d4ff', fontSize: 12, fontWeight: 600, textDecoration: 'none',
                    display: 'flex', alignItems: 'center', gap: 6,
                  }}
                >
                  <svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                  Download PDF
                </a>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
