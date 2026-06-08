const SOURCE_META = {
  virustotal:   { label: 'VirusTotal',     color: 'text-blue-400',   icon: '🔬' },
  abuseipdb:    { label: 'AbuseIPDB',      color: 'text-orange-400', icon: '🚨' },
  alienvault:   { label: 'AlienVault OTX', color: 'text-purple-400', icon: '👾' },
  urlhaus:      { label: 'URLhaus',        color: 'text-red-400',    icon: '🔗' },
  threatfox:    { label: 'ThreatFox',      color: 'text-teal-400',   icon: '🦊' },
  malwarebazaar:{ label: 'MalwareBazaar',  color: 'text-pink-400',   icon: '🧬' },
}

function StatusBadge({ status }) {
  if (status === 'found')           return <span className="px-2 py-0.5 rounded-full bg-red-900/50 text-red-300 text-xs">Found</span>
  if (status === 'not_found')       return <span className="px-2 py-0.5 rounded-full bg-green-900/50 text-green-300 text-xs">Not found</span>
  if (status === 'no_api_key')      return <span className="px-2 py-0.5 rounded-full bg-slate-700 text-slate-400 text-xs">No API key</span>
  if (status === 'invalid_api_key') return <span className="px-2 py-0.5 rounded-full bg-yellow-900/50 text-yellow-300 text-xs">Invalid key</span>
  return <span className="px-2 py-0.5 rounded-full bg-slate-700 text-slate-400 text-xs">N/A</span>
}

function VTDetails({ data }) {
  if (data.status !== 'found') return null
  return (
    <div className="grid grid-cols-4 gap-2 mt-3">
      {[
        { label: 'Malicious', value: data.malicious, color: 'text-red-400' },
        { label: 'Suspicious', value: data.suspicious, color: 'text-orange-400' },
        { label: 'Harmless', value: data.harmless, color: 'text-green-400' },
        { label: 'Total', value: data.total, color: 'text-slate-300' },
      ].map(({ label, value, color }) => (
        <div key={label} className="text-center bg-slate-800 rounded-lg p-2">
          <div className={`text-lg font-bold ${color}`}>{value ?? '—'}</div>
          <div className="text-xs text-slate-500">{label}</div>
        </div>
      ))}
    </div>
  )
}

function AbuseDetails({ data }) {
  if (data.status !== 'found') return null
  return (
    <div className="mt-3 space-y-1 text-xs text-slate-400">
      <div className="flex justify-between">
        <span>Confidence Score</span>
        <span className="text-orange-300 font-mono font-bold">{data.confidence_score}%</span>
      </div>
      <div className="flex justify-between">
        <span>Total Reports</span>
        <span className="text-slate-300">{data.total_reports}</span>
      </div>
      {data.isp && <div className="flex justify-between">
        <span>ISP</span>
        <span className="text-slate-300 truncate max-w-[150px]">{data.isp}</span>
      </div>}
      {data.is_tor && <div className="text-red-400 font-medium">⚠ Tor Exit Node</div>}
    </div>
  )
}

function AlienVaultDetails({ data }) {
  if (data.status !== 'found') return null
  return (
    <div className="mt-3 space-y-1 text-xs text-slate-400">
      <div className="flex justify-between">
        <span>Pulse Count</span>
        <span className="text-purple-300 font-bold">{data.pulse_count}</span>
      </div>
      {data.tags?.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1">
          {data.tags.slice(0, 5).map(tag => (
            <span key={tag} className="px-1.5 py-0.5 rounded bg-purple-900/40 text-purple-300 text-xs">{tag}</span>
          ))}
        </div>
      )}
    </div>
  )
}

function URLhausDetails({ data }) {
  if (data.status !== 'found') return null
  return (
    <div className="mt-3 space-y-1 text-xs text-slate-400">
      <div className="flex justify-between">
        <span>URL Status</span>
        <span className={data.url_status === 'online' ? 'text-red-400 font-bold' : 'text-green-400'}>
          {data.url_status || '—'}
        </span>
      </div>
      {data.threat && <div className="flex justify-between">
        <span>Threat</span>
        <span className="text-red-300">{data.threat}</span>
      </div>}
    </div>
  )
}

function ThreatFoxDetails({ data }) {
  if (data.status !== 'found') return null
  return (
    <div className="mt-3 space-y-1 text-xs text-slate-400">
      <div className="flex justify-between">
        <span>Confidence</span>
        <span className="text-teal-300 font-mono font-bold">{data.confidence_level}%</span>
      </div>
      <div className="flex justify-between">
        <span>IOC Matches</span>
        <span className="text-slate-300">{data.ioc_count}</span>
      </div>
      {data.malware?.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1">
          {data.malware.slice(0, 3).map(m => (
            <span key={m} className="px-1.5 py-0.5 rounded bg-teal-900/40 text-teal-300 text-xs">{m}</span>
          ))}
        </div>
      )}
    </div>
  )
}

function MalwareBazaarDetails({ data }) {
  if (data.status !== 'found') return null
  return (
    <div className="mt-3 space-y-1 text-xs text-slate-400">
      {data.signature && (
        <div className="flex justify-between">
          <span>Signature</span>
          <span className="text-pink-300 font-medium truncate max-w-[150px]">{data.signature}</span>
        </div>
      )}
      <div className="flex justify-between">
        <span>AV Detections</span>
        <span className="text-slate-300">{data.detections} / {data.total_vendors}</span>
      </div>
      {data.file_type && (
        <div className="flex justify-between">
          <span>File Type</span>
          <span className="text-slate-300">{data.file_type}</span>
        </div>
      )}
      {data.tags?.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1">
          {data.tags.slice(0, 3).map(tag => (
            <span key={tag} className="px-1.5 py-0.5 rounded bg-pink-900/40 text-pink-300 text-xs">{tag}</span>
          ))}
        </div>
      )}
    </div>
  )
}

export default function SourceResultCard({ source, data }) {
  const meta = SOURCE_META[source] || { label: source, color: 'text-slate-400', icon: '📊' }

  if (!data) {
    return (
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 opacity-50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-lg">{meta.icon}</span>
            <span className={`font-medium text-sm ${meta.color}`}>{meta.label}</span>
          </div>
          <span className="px-2 py-0.5 rounded-full bg-slate-700 text-slate-500 text-xs">No data</span>
        </div>
      </div>
    )
  }

  return (
    <div className="bg-slate-800/80 border border-slate-700 rounded-xl p-4">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <span className="text-lg">{meta.icon}</span>
          <span className={`font-medium text-sm ${meta.color}`}>{meta.label}</span>
        </div>
        <StatusBadge status={data.status} />
      </div>
      {source === 'virustotal'    && <VTDetails data={data} />}
      {source === 'abuseipdb'     && <AbuseDetails data={data} />}
      {source === 'alienvault'    && <AlienVaultDetails data={data} />}
      {source === 'urlhaus'       && <URLhausDetails data={data} />}
      {source === 'threatfox'     && <ThreatFoxDetails data={data} />}
      {source === 'malwarebazaar' && <MalwareBazaarDetails data={data} />}
    </div>
  )
}
