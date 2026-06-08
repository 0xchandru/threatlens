import ThreatScoreGauge from './ThreatScoreGauge'
import SourceResultCard from './SourceResultCard'
import MITREHeatmap from './MITREHeatmap'
import AnalystPanel from './AnalystPanel'
import { useMutation } from '@tanstack/react-query'
import api from '../lib/api'

const SOURCES = ['virustotal', 'abuseipdb', 'alienvault', 'urlhaus', 'threatfox', 'malwarebazaar']

export default function LookupResult({ result, onClose }) {
  if (!result) return null

  const { ioc, score, risk_level, confidence, breakdown, mitre, results, errors, query_time_ms, notes, tags, source } = result

  const generateReport = useMutation({
    mutationFn: () => api.post('/reports/generate', { ioc_value: ioc.value, scan_id: result.scan_id }),
    onSuccess: async (res) => {
      const reportId = res.data.id
      window.open(`/api/v1/reports/${reportId}/download`, '_blank')
    },
  })

  return (
    <div className="space-y-4 mt-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-slate-100 font-mono">{ioc?.value}</h2>
          <div className="flex items-center gap-2 mt-1">
            <span className="px-2 py-0.5 rounded bg-slate-700 text-slate-400 text-xs uppercase font-mono">
              {ioc?.type}
            </span>
            <span className="text-xs text-slate-500">
              {source === 'cache' ? '⚡ Cached result' : `${query_time_ms}ms · 6 sources queried in parallel`}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => generateReport.mutate()}
            disabled={generateReport.isPending}
            className="px-3 py-2 bg-slate-700 hover:bg-slate-600 disabled:opacity-40 rounded-lg text-sm text-slate-300 transition-colors"
          >
            {generateReport.isPending ? 'Generating...' : '📄 PDF Report'}
          </button>
          <button onClick={onClose}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-sm text-slate-400 transition-colors">
            ✕ Clear
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-1">
          <ThreatScoreGauge
            score={score}
            riskLevel={risk_level}
            confidence={confidence}
            queryTimeMs={query_time_ms}
          />
          {breakdown && Object.keys(breakdown).length > 0 && (
            <div className="mt-3 bg-slate-900 border border-slate-700 rounded-xl p-4">
              <h4 className="text-xs font-semibold text-slate-400 uppercase mb-2">Score Breakdown</h4>
              <div className="space-y-1.5">
                {Object.entries(breakdown).map(([source, val]) => (
                  <div key={source} className="flex justify-between items-center">
                    <span className="text-xs text-slate-400 capitalize">{source}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-20 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-sky-500 rounded-full"
                          style={{ width: `${Math.min((val / 32) * 100, 100)}%` }}
                        />
                      </div>
                      <span className="text-xs text-slate-300 font-mono w-8 text-right">{val}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="lg:col-span-3 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
            {SOURCES.map(src => (
              <SourceResultCard key={src} source={src} data={results?.[src]} />
            ))}
          </div>
          {errors?.length > 0 && (
            <div className="bg-yellow-900/20 border border-yellow-800 rounded-lg p-3">
              <p className="text-xs text-yellow-400 font-medium mb-1">API Errors</p>
              {errors.map((e, i) => (
                <p key={i} className="text-xs text-yellow-300">{e.source}: {e.error}</p>
              ))}
            </div>
          )}
        </div>
      </div>

      {mitre?.length > 0 && <MITREHeatmap techniques={mitre} />}

      <AnalystPanel iocValue={ioc?.value} notes={notes || []} tags={tags || []} />
    </div>
  )
}
