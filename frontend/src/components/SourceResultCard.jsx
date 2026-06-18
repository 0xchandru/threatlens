const SOURCE_META = {
  virustotal:    { label: 'VirusTotal',     accent: '#4285f4', icon: '🔬', desc: 'Multi-AV engine scan' },
  abuseipdb:     { label: 'AbuseIPDB',      accent: '#ff6b35', icon: '🚨', desc: 'Abuse reports database' },
  alienvault:    { label: 'AlienVault OTX', accent: '#7c3aed', icon: '👾', desc: 'Open threat exchange' },
  urlhaus:       { label: 'URLhaus',        accent: '#ff4444', icon: '🔗', desc: 'Malware URL tracker' },
  threatfox:     { label: 'ThreatFox',      accent: '#00d4ff', icon: '🦊', desc: 'IOC sharing platform' },
  malwarebazaar: { label: 'MalwareBazaar',  accent: '#f472b6', icon: '🧬', desc: 'Malware sample repository' },
}

function StatusBadge({ status }) {
  const configs = {
    found:           { bg: 'rgba(255,68,68,0.12)',   color: '#ff6b6b', text: 'DETECTED' },
    not_found:       { bg: 'rgba(0,255,136,0.1)',    color: '#00ff88', text: 'CLEAN' },
    no_api_key:      { bg: 'rgba(136,146,164,0.1)',  color: '#8892a4', text: 'NO KEY' },
    invalid_api_key: { bg: 'rgba(255,170,0,0.1)',    color: '#ffaa00', text: 'BAD KEY' },
    error:           { bg: 'rgba(255,170,0,0.1)',    color: '#ffaa00', text: 'ERROR' },
  }
  const cfg = configs[status] || { bg: 'rgba(136,146,164,0.1)', color: '#8892a4', text: 'N/A' }
  return (
    <span style={{ padding: '2px 8px', borderRadius: 20, fontSize: 10, fontWeight: 700, background: cfg.bg, color: cfg.color }}>
      {cfg.text}
    </span>
  )
}

function Row({ label, value, color }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11, padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
      <span style={{ color: '#8892a4' }}>{label}</span>
      <span style={{ color: color || '#c8d6e8', fontWeight: 600, maxWidth: 160, textAlign: 'right', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{value}</span>
    </div>
  )
}

function TagList({ tags, color }) {
  if (!tags?.length) return null
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
      {tags.slice(0, 5).map(t => (
        <span key={t} style={{ padding: '1px 7px', borderRadius: 10, fontSize: 10, background: `${color}18`, color: color, border: `1px solid ${color}30` }}>
          {t}
        </span>
      ))}
    </div>
  )
}

function VTDetails({ data, accent }) {
  if (data.status !== 'found') return null
  const total = data.total || 1
  const pct = ((data.malicious || 0) / total * 100).toFixed(0)
  return (
    <div style={{ marginTop: 10 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 6, marginBottom: 8 }}>
        {[
          { label: 'Malicious',  value: data.malicious,  color: '#ff4444' },
          { label: 'Suspicious', value: data.suspicious, color: '#ffaa00' },
          { label: 'Harmless',   value: data.harmless,   color: '#00ff88' },
          { label: 'Total',      value: data.total,      color: '#c8d6e8' },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ textAlign: 'center', background: 'rgba(255,255,255,0.04)', borderRadius: 6, padding: '6px 4px' }}>
            <div style={{ fontSize: 16, fontWeight: 700, color }}>{value ?? 0}</div>
            <div style={{ fontSize: 9, color: '#8892a4' }}>{label}</div>
          </div>
        ))}
      </div>
      <div style={{ height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: pct > 50 ? '#ff4444' : pct > 20 ? '#ffaa00' : '#00ff88', borderRadius: 2 }} />
      </div>
      <div style={{ fontSize: 10, color: '#8892a4', marginTop: 4 }}>{pct}% detection rate</div>
      {data.tags?.length > 0 && <TagList tags={data.tags} color={accent} />}
    </div>
  )
}

function AbuseDetails({ data, accent }) {
  if (data.status !== 'found') return null
  const score = data.confidence_score || 0
  return (
    <div style={{ marginTop: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        <div style={{ fontSize: 26, fontWeight: 800, color: score > 50 ? '#ff4444' : score > 20 ? '#ffaa00' : '#00ff88', fontFamily: 'monospace' }}>{score}%</div>
        <div style={{ fontSize: 10, color: '#8892a4' }}>abuse confidence</div>
      </div>
      <Row label="Total Reports" value={data.total_reports} />
      {data.country_code && <Row label="Country" value={data.country_code} />}
      {data.isp && <Row label="ISP" value={data.isp} />}
      {data.usage_type && <Row label="Usage Type" value={data.usage_type} />}
      {data.is_tor && <div style={{ marginTop: 6, fontSize: 11, color: '#ff4444', fontWeight: 700 }}>⚠ Tor Exit Node</div>}
    </div>
  )
}

function AlienVaultDetails({ data, accent }) {
  if (data.status !== 'found') return null
  return (
    <div style={{ marginTop: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        <div style={{ fontSize: 26, fontWeight: 800, color: accent, fontFamily: 'monospace' }}>{data.pulse_count}</div>
        <div style={{ fontSize: 10, color: '#8892a4' }}>threat pulses</div>
      </div>
      {data.malware_families?.length > 0 && <Row label="Malware" value={data.malware_families.slice(0,3).join(', ')} color="#ff4444" />}
      {data.adversaries?.length > 0 && <Row label="Adversaries" value={data.adversaries.slice(0,2).join(', ')} color="#ffaa00" />}
      {data.tags?.length > 0 && <TagList tags={data.tags} color={accent} />}
    </div>
  )
}

function URLhausDetails({ data, accent }) {
  if (data.status !== 'found') return null
  const isOnline = data.url_status === 'online'
  return (
    <div style={{ marginTop: 10 }}>
      <Row label="Status" value={(data.url_status || 'unknown').toUpperCase()} color={isOnline ? '#ff4444' : '#00ff88'} />
      {data.threat && <Row label="Threat Type" value={data.threat} color="#ff4444" />}
      {data.reporter && <Row label="Reporter" value={data.reporter} />}
      {data.date_added && <Row label="Date Added" value={new Date(data.date_added).toLocaleDateString()} />}
      {data.tags?.length > 0 && <TagList tags={data.tags} color={accent} />}
    </div>
  )
}

function ThreatFoxDetails({ data, accent }) {
  if (data.status !== 'found') return null
  return (
    <div style={{ marginTop: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        <div style={{ fontSize: 26, fontWeight: 800, color: accent, fontFamily: 'monospace' }}>{data.confidence_level}%</div>
        <div style={{ fontSize: 10, color: '#8892a4' }}>confidence</div>
      </div>
      <Row label="IOC Matches" value={data.ioc_count} />
      {data.threat_types?.length > 0 && <Row label="Threat Types" value={data.threat_types.slice(0,2).join(', ')} color="#ffaa00" />}
      {data.malware?.length > 0 && <TagList tags={data.malware} color={accent} />}
    </div>
  )
}

function MalwareBazaarDetails({ data, accent }) {
  if (data.status !== 'found') return null
  return (
    <div style={{ marginTop: 10 }}>
      {data.signature && <Row label="Signature" value={data.signature} color={accent} />}
      <Row label="AV Detections" value={`${data.detections || 0} / ${data.total_vendors || '?'}`} color={data.detections > 10 ? '#ff4444' : '#ffaa00'} />
      {data.file_type && <Row label="File Type" value={data.file_type} />}
      {data.tags?.length > 0 && <TagList tags={data.tags} color={accent} />}
    </div>
  )
}

export default function SourceResultCard({ source, data }) {
  const meta = SOURCE_META[source] || { label: source, accent: '#8892a4', icon: '📊', desc: '' }

  const cardStyle = {
    background: '#141b2d',
    border: `1px solid ${data?.status === 'found' ? `${meta.accent}30` : 'rgba(255,255,255,0.06)'}`,
    borderRadius: 12,
    padding: 16,
    transition: 'border-color 0.2s',
  }

  if (!data) {
    return (
      <div style={{ ...cardStyle, opacity: 0.45 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 18 }}>{meta.icon}</span>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#8892a4' }}>{meta.label}</div>
            <div style={{ fontSize: 10, color: '#8892a4', opacity: 0.6 }}>{meta.desc}</div>
          </div>
          <span style={{ marginLeft: 'auto', fontSize: 10, color: '#8892a4', background: 'rgba(255,255,255,0.04)', padding: '2px 8px', borderRadius: 10 }}>No data</span>
        </div>
      </div>
    )
  }

  return (
    <div style={cardStyle}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 18 }}>{meta.icon}</span>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: meta.accent }}>{meta.label}</div>
            <div style={{ fontSize: 10, color: '#8892a4' }}>{meta.desc}</div>
          </div>
        </div>
        <StatusBadge status={data.status} />
      </div>
      {source === 'virustotal'    && <VTDetails data={data} accent={meta.accent} />}
      {source === 'abuseipdb'     && <AbuseDetails data={data} accent={meta.accent} />}
      {source === 'alienvault'    && <AlienVaultDetails data={data} accent={meta.accent} />}
      {source === 'urlhaus'       && <URLhausDetails data={data} accent={meta.accent} />}
      {source === 'threatfox'     && <ThreatFoxDetails data={data} accent={meta.accent} />}
      {source === 'malwarebazaar' && <MalwareBazaarDetails data={data} accent={meta.accent} />}
    </div>
  )
}
