import { useQuery } from '@tanstack/react-query'
import api from '../lib/api'

export default function ReportsPage() {
  const { data: reports, isLoading } = useQuery({
    queryKey: ['reports'],
    queryFn: () => api.get('/reports').then(r => r.data),
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Reports</h1>
        <p className="text-slate-400 text-sm mt-1">
          Generated PDF threat intelligence reports. Use the IOC Lookup page to generate new reports.
        </p>
      </div>

      {isLoading && (
        <div className="text-center text-slate-400 animate-pulse">Loading reports...</div>
      )}

      {reports?.length === 0 && (
        <div className="bg-slate-900 border border-slate-700 border-dashed rounded-xl p-8 text-center">
          <div className="text-4xl mb-3">📋</div>
          <h3 className="text-lg font-semibold text-slate-300 mb-2">No reports yet</h3>
          <p className="text-slate-500 text-sm">
            After running an IOC lookup, click "PDF Report" to generate a professional threat intelligence report.
          </p>
        </div>
      )}

      {reports?.length > 0 && (
        <div className="space-y-2">
          {reports.map(report => (
            <div key={report.id}
              className="bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 flex items-center justify-between">
              <div>
                <div className="text-sm font-mono text-slate-200">{report.filename}</div>
                <div className="text-xs text-slate-500 mt-0.5">
                  {report.created_at ? new Date(report.created_at).toLocaleString() : '—'}
                </div>
              </div>
              <a
                href={`/api/v1/reports/${report.id}/download`}
                target="_blank"
                rel="noreferrer"
                className="px-3 py-1.5 bg-sky-700 hover:bg-sky-600 rounded-lg text-xs text-white transition-colors"
              >
                📥 Download PDF
              </a>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
