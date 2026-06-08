import { useState } from 'react'
import IOCSearchBar from '../components/IOCSearchBar'
import LookupResult from '../components/LookupResult'

const EXAMPLES = [
  { label: 'Malicious IP', value: '185.220.101.47' },
  { label: 'Known domain', value: 'google.com' },
  { label: 'Malware hash (SHA256)', value: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' },
]

export default function LookupPage() {
  const [result, setResult] = useState(null)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">IOC Lookup</h1>
        <p className="text-slate-400 text-sm mt-1">
          Query 5 threat intelligence sources in parallel — VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, GreyNoise
        </p>
      </div>

      <div className="bg-slate-900 border border-slate-700 rounded-xl p-6">
        <IOCSearchBar onResult={setResult} />

        <div className="mt-4 flex flex-wrap gap-2">
          <span className="text-xs text-slate-500">Examples:</span>
          {EXAMPLES.map(ex => (
            <button
              key={ex.value}
              onClick={() => {
                navigator.clipboard?.writeText(ex.value)
              }}
              className="text-xs text-sky-400 hover:text-sky-300 transition-colors"
              title={ex.value}
            >
              {ex.label}
            </button>
          ))}
        </div>

        <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 gap-3">
          {[
            { icon: '🌐', label: 'IP Addresses', desc: 'IPv4 and IPv6' },
            { icon: '🔗', label: 'Domains & URLs', desc: 'Full URLs or bare domains' },
            { icon: '🔑', label: 'File Hashes', desc: 'MD5, SHA1, SHA256' },
          ].map(item => (
            <div key={item.label} className="bg-slate-800 rounded-lg p-3 flex items-start gap-3">
              <span className="text-xl">{item.icon}</span>
              <div>
                <div className="text-sm font-medium text-slate-300">{item.label}</div>
                <div className="text-xs text-slate-500">{item.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {result && (
        <LookupResult result={result} onClose={() => setResult(null)} />
      )}
    </div>
  )
}
