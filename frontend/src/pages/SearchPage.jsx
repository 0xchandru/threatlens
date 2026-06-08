import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import api from '../lib/api'
import { getRiskConfig } from '../lib/scoring'

const RISK_LEVELS = ['', 'critical', 'malicious', 'suspicious', 'low', 'clean']
const IOC_TYPES   = ['', 'ip', 'domain', 'url', 'md5', 'sha1', 'sha256']

export default function SearchPage() {
  const [tag,       setTag]       = useState('')
  const [riskLevel, setRiskLevel] = useState('')
  const [iocType,   setIocType]   = useState('')
  const [submitted, setSubmitted] = useState(false)

  const { data: results, isFetching } = useQuery({
    queryKey: ['search', tag, riskLevel, iocType],
    queryFn: () => {
      const params = new URLSearchParams()
      if (tag)       params.append('tag',        tag)
      if (riskLevel) params.append('risk_level', riskLevel)
      if (iocType)   params.append('ioc_type',   iocType)
      return api.get(`/search?${params}`).then(r => r.data)
    },
    enabled: submitted,
  })

  const handleSearch = (e) => {
    e.preventDefault()
    setSubmitted(true)
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Search IOCs</h1>
        <p className="text-slate-400 text-sm mt-1">Filter and search through investigated indicators</p>
      </div>

      <form onSubmit={handleSearch}
        className="bg-slate-900 border border-slate-700 rounded-xl p-4 flex flex-wrap gap-3 items-end">
        <div className="flex-1 min-w-48">
          <label className="block text-xs text-slate-400 mb-1">Tag</label>
          <input
            value={tag} onChange={e => setTag(e.target.value)}
            placeholder="e.g. c2, ransomware"
            className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-sky-500"
          />
        </div>
        <div>
          <label className="block text-xs text-slate-400 mb-1">Risk Level</label>
          <select value={riskLevel} onChange={e => setRiskLevel(e.target.value)}
            className="bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none focus:border-sky-500">
            {RISK_LEVELS.map(r => (
              <option key={r} value={r}>{r || 'All Risk Levels'}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs text-slate-400 mb-1">IOC Type</label>
          <select value={iocType} onChange={e => setIocType(e.target.value)}
            className="bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none focus:border-sky-500">
            {IOC_TYPES.map(t => (
              <option key={t} value={t}>{t || 'All Types'}</option>
            ))}
          </select>
        </div>
        <button type="submit"
          className="px-5 py-2 bg-sky-600 hover:bg-sky-500 rounded-lg text-sm text-white font-medium transition-colors">
          Search
        </button>
      </form>

      {isFetching && (
        <div className="text-center text-slate-400 animate-pulse">Searching...</div>
      )}

      {results && (
        <div className="space-y-2">
          <p className="text-xs text-slate-500">{results.length} result{results.length !== 1 ? 's' : ''}</p>
          {results.length === 0 ? (
            <div className="text-center py-8 text-slate-500">No IOCs found matching your filters</div>
          ) : (
            <div className="space-y-2">
              {results.map(ioc => (
                <div key={ioc.id}
                  className="bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 flex items-center justify-between hover:border-slate-600 transition-colors">
                  <div>
                    <span className="font-mono text-sm text-slate-200">{ioc.value}</span>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-400 text-xs uppercase font-mono">
                        {ioc.ioc_type}
                      </span>
                      <span className="text-xs text-slate-500">
                        {ioc.lookup_count} lookup{ioc.lookup_count !== 1 ? 's' : ''}
                      </span>
                      {ioc.last_seen && (
                        <span className="text-xs text-slate-500">
                          Last seen: {new Date(ioc.last_seen).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>
                  <Link
                    to={`/lookup?q=${encodeURIComponent(ioc.value)}`}
                    className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-xs text-slate-300 transition-colors"
                  >
                    View
                  </Link>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!submitted && (
        <div className="text-center py-12 text-slate-600">
          Use the filters above to search your investigated IOCs
        </div>
      )}
    </div>
  )
}
