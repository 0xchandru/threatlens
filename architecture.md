# ThreatLens — Architecture & SecOps Integration Guide

> **Purpose:** This document explains ThreatLens internals and provides exact integration patterns for embedding ThreatLens enrichment inside a SecOps Mini SIEM alert page.

---

## Table of Contents

1. [System Architecture Overview](#1-system-architecture-overview)
2. [Data Flow — Single IOC Lookup](#2-data-flow--single-ioc-lookup)
3. [Database Schema (Entity Relationships)](#3-database-schema)
4. [API Contract Reference](#4-api-contract-reference)
5. [SecOps Integration — Step by Step](#5-secops-integration--step-by-step)
6. [Frontend Component Integration](#6-frontend-component-integration)
7. [Response Shape Reference](#7-response-shape-reference)
8. [Risk Level → UI Color Mapping](#8-risk-level--ui-color-mapping)
9. [Environment & CORS Setup](#9-environment--cors-setup)
10. [Common Integration Patterns](#10-common-integration-patterns)

---

## 1. System Architecture Overview

```
╔══════════════════════════════════════════════════════════════════════╗
║                        THREATLENS SYSTEM                            ║
║                                                                      ║
║  ┌─────────────────────────────────────────────────────────────┐    ║
║  │  React Frontend  (port 5000, host: 0.0.0.0)                │    ║
║  │  Vite dev proxy: /api  ──────────►  localhost:8000          │    ║
║  └─────────────────────────────────────────────────────────────┘    ║
║                           │                                          ║
║  ┌─────────────────────────▼───────────────────────────────────┐    ║
║  │  FastAPI Backend  (port 8000, host: localhost)              │    ║
║  │                                                              │    ║
║  │  ┌──────────────────┐   ┌──────────────────────────────┐   │    ║
║  │  │   IOC Normalizer │   │   Parallel Query Engine      │   │    ║
║  │  │   (type detect)  │──►│   asyncio.gather (5 sources) │   │    ║
║  │  └──────────────────┘   └──────────┬───────────────────┘   │    ║
║  │                                    │                         │    ║
║  │                          ┌─────────▼──────────┐             │    ║
║  │                          │   Scorer + MITRE   │             │    ║
║  │                          │   Mapper           │             │    ║
║  │                          └─────────┬──────────┘             │    ║
║  │                                    │                         │    ║
║  │                          ┌─────────▼──────────┐             │    ║
║  │                          │  PostgreSQL / SQLite│             │    ║
║  │                          │  (persist + cache) │             │    ║
║  │                          └────────────────────┘             │    ║
║  └─────────────────────────────────────────────────────────────┘    ║
╚══════════════════════════════════════════════════════════════════════╝
                  ▲ Cross-origin REST API (CORS enabled)
                  │
╔═════════════════╧════════════════════════════════════════════════════╗
║                     SECOPS MINI SIEM                                 ║
║                                                                      ║
║  Alert Table Row ──► [Enrich] button ──► ThreatLens API             ║
║         │                                      │                     ║
║         └──────── ThreatBadge component ◄──────┘                    ║
║                   (score + risk chip)                                ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## 2. Data Flow — Single IOC Lookup

```
SecOps Alert Page
      │
      │  POST /api/v1/ioc/lookup  { "value": "1.2.3.4" }
      ▼
FastAPI  app/api/v1/ioc.py  →  lookup_ioc()
      │
      ├─► IOC Normalizer (app/services/normalizer.py)
      │     detect_and_normalize("1.2.3.4")  →  NormalizedIOC(type=ip)
      │     is_private_ip() check  →  reject 10.x, 192.168.x, 172.16.x
      │
      ├─► Cache check  (crud.get_recent_scan, 60-min window)
      │     HIT  →  return {"source": "cache", ...}  immediately
      │     MISS →  continue
      │
      ├─► Parallel aggregation  (app/services/aggregator.py)
      │     asyncio.gather([
      │       virustotal.query(),      ─┐
      │       abuseipdb.query(),        │  All fire simultaneously
      │       alienvault.query(),       │  ~800ms total
      │       urlhaus.query(),          │
      │       greynoise.query(),       ─┘
      │     ], return_exceptions=True)
      │     Each returns:  dict | None | Exception
      │
      ├─► Scorer  (app/services/scorer.py)
      │     calculate_composite_score(results)
      │     →  ScoreResult(composite_score, risk_level, breakdown, confidence)
      │
      ├─► MITRE Mapper  (app/services/mitre.py)
      │     map_to_mitre(results)
      │     →  [MITRETechnique, ...]
      │
      ├─► DB Persist  (app/crud.py)
      │     get_or_create_ioc()
      │     create_scan()           ←  stores raw_results as JSONB
      │     MITREMapping rows
      │
      ├─► Background Task (FastAPI BackgroundTasks)
      │     run_enrichment()        ←  IP only, non-blocking
      │     →  ASN, country, rDNS stored to enrichment_data
      │
      └─► JSON Response
            { source, ioc, scan_id, score, risk_level, confidence,
              breakdown, mitre, results, errors, query_time_ms }
```

---

## 3. Database Schema

```
┌─────────────────────────────┐
│           iocs              │
├─────────────────────────────┤
│ id          INTEGER  PK     │
│ value       STRING   UNIQUE │◄── Lookup key
│ ioc_type    ENUM            │    ip|domain|url|md5|sha1|sha256
│ first_seen  DATETIME        │
│ last_seen   DATETIME        │
│ lookup_count INTEGER        │
└──────────┬──────────────────┘
           │ 1 : N
┌──────────▼──────────────────┐     ┌──────────────────────────┐
│           scans             │     │       mitre_mappings      │
├─────────────────────────────┤     ├──────────────────────────┤
│ id              INTEGER  PK │     │ id           INTEGER  PK │
│ ioc_id          FK → iocs   │     │ scan_id      FK → scans  │
│ timestamp       DATETIME    │     │ technique_id STRING       │
│ composite_score FLOAT       │◄───►│ technique    STRING       │
│ risk_level      STRING      │     │ tactic       STRING       │
│ raw_results     JSON        │     │ confidence   STRING       │
│ sources_queried JSON        │     │ source       STRING       │
│ error_sources   JSON        │     └──────────────────────────┘
│ query_time_ms   INTEGER     │
└─────────────────────────────┘

┌──────────────────────────────┐     ┌──────────────────────────┐
│        analyst_notes         │     │        threat_tags        │
├──────────────────────────────┤     ├──────────────────────────┤
│ id         INTEGER  PK       │     │ id         INTEGER  PK   │
│ ioc_id     FK → iocs         │     │ ioc_id     FK → iocs     │
│ note       TEXT              │     │ tag        STRING  INDEX  │
│ analyst    STRING            │     │ created_by STRING        │
│ created_at DATETIME          │     │ created_at DATETIME      │
└──────────────────────────────┘     └──────────────────────────┘

┌──────────────────────────────┐     ┌──────────────────────────┐
│        enrichment_data       │     │          reports          │
├──────────────────────────────┤     ├──────────────────────────┤
│ id           INTEGER  PK     │     │ id         INTEGER  PK   │
│ ioc_id       FK UNIQUE       │     │ ioc_id     FK → iocs     │
│ asn          STRING          │     │ scan_id    FK → scans    │
│ asn_org      STRING          │     │ filename   STRING        │
│ country_code STRING          │     │ pdf_data   BYTEA         │
│ country_name STRING          │     │ created_at DATETIME      │
│ city         STRING          │     └──────────────────────────┘
│ rdns         STRING          │
│ enriched_at  DATETIME        │
└──────────────────────────────┘
```

---

## 4. API Contract Reference

### Base URL
```
Development:  http://localhost:8000/api/v1
Production:   https://your-threatlens.replit.app/api/v1
```

### Endpoints

| Method | Path | Purpose | Key Params |
|--------|------|---------|------------|
| `POST` | `/ioc/lookup` | Submit IOC, get score + results | `{ value }` |
| `GET`  | `/ioc/{value}` | Get IOC detail + enrichment | — |
| `GET`  | `/ioc/{value}/history` | All historical scans | — |
| `POST` | `/ioc/{value}/notes` | Add analyst note | `{ note, analyst }` |
| `PUT`  | `/ioc/{value}/tags` | Replace tag set | `{ tags: [] }` |
| `DELETE` | `/ioc/{value}/notes/{id}` | Delete a note | — |
| `GET`  | `/dashboard/stats` | Aggregate dashboard metrics | — |
| `GET`  | `/dashboard/timeline` | Scan volume over time | `?days=30` |
| `GET`  | `/search` | Filter IOCs | `?tag=&risk_level=&ioc_type=` |
| `POST` | `/reports/generate` | Generate PDF | `{ ioc_value, scan_id }` |
| `GET`  | `/reports` | List reports | — |
| `GET`  | `/reports/{id}/download` | Download PDF | — |
| `GET`  | `/health` | Health check | — |

### Risk Levels (score thresholds)
```
0  – 19  →  clean        (green)
20 – 39  →  low          (blue)
40 – 59  →  suspicious   (yellow)
60 – 79  →  malicious    (orange)
80 – 100 →  critical     (red)
```

---

## 5. SecOps Integration — Step by Step

### Step 1 — Enable CORS

In ThreatLens `.env`, add your SecOps domain:

```env
CORS_ORIGINS=https://your-secops.replit.app,http://localhost:3000
```

Then update `backend/app/main.py` to read `CORS_ORIGINS` from config:

```python
# In config.py, add:
CORS_ORIGINS: str = "*"

# In main.py, replace allow_origins:
origins = [o.strip() for o in settings.CORS_ORIGINS.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Step 2 — Add ThreatLens URL to SecOps

In your SecOps project's environment:

```env
VITE_THREATLENS_URL=https://your-threatlens.replit.app
# or for development:
VITE_THREATLENS_URL=http://localhost:8000
```

### Step 3 — Create the ThreatLens API client in SecOps

Create `src/lib/threatlens.js` in your SecOps project:

```javascript
const THREATLENS_URL = import.meta.env.VITE_THREATLENS_URL || 'http://localhost:8000';

export async function enrichIOC(value) {
  try {
    const res = await fetch(`${THREATLENS_URL}/api/v1/ioc/lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value }),
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    return { error: err.message, score: null, risk_level: 'unknown' };
  }
}

export async function getIOCHistory(value) {
  const res = await fetch(`${THREATLENS_URL}/api/v1/ioc/${encodeURIComponent(value)}/history`);
  return res.json();
}

export function getRiskColor(riskLevel) {
  const colors = {
    clean:      { bg: '#14532d', text: '#86efac', border: '#166534' },
    low:        { bg: '#1e3a5f', text: '#93c5fd', border: '#1e40af' },
    suspicious: { bg: '#422006', text: '#fde68a', border: '#92400e' },
    malicious:  { bg: '#431407', text: '#fed7aa', border: '#9a3412' },
    critical:   { bg: '#450a0a', text: '#fca5a5', border: '#991b1b' },
    unknown:    { bg: '#1e293b', text: '#94a3b8', border: '#334155' },
  };
  return colors[riskLevel] || colors.unknown;
}
```

### Step 4 — ThreatBadge Component

Add `src/components/ThreatBadge.jsx` to your SecOps project:

```jsx
import { useState } from 'react';
import { enrichIOC, getRiskColor } from '../lib/threatlens';

export default function ThreatBadge({ iocValue, autoEnrich = false }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  const enrich = async () => {
    setLoading(true);
    setError(null);
    const result = await enrichIOC(iocValue);
    if (result.error) setError(result.error);
    else setData(result);
    setLoading(false);
  };

  // Auto-enrich on mount if prop set
  // useEffect(() => { if (autoEnrich) enrich(); }, []);

  if (loading) return (
    <span style={{ color: '#94a3b8', fontSize: 11 }}>⚡ querying...</span>
  );

  if (!data) return (
    <button
      onClick={enrich}
      style={{
        padding: '2px 8px', borderRadius: 4, fontSize: 11,
        background: '#1e293b', color: '#7dd3fc',
        border: '1px solid #334155', cursor: 'pointer'
      }}
    >
      🔍 Enrich
    </button>
  );

  const { bg, text, border } = getRiskColor(data.risk_level);

  return (
    <span
      title={`Score: ${data.score} | ${data.query_time_ms}ms | ${data.confidence} confidence`}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        padding: '2px 8px', borderRadius: 4, fontSize: 11,
        background: bg, color: text, border: `1px solid ${border}`,
        fontFamily: 'monospace', cursor: 'default',
      }}
    >
      {data.score?.toFixed(0)}/100 · {data.risk_level.toUpperCase()}
    </span>
  );
}
```

### Step 5 — Use in Alert Table

In your SecOps alert table row:

```jsx
import ThreatBadge from '../components/ThreatBadge';

// In your alert table columns:
{
  header: 'Threat Intel',
  cell: ({ row }) => (
    <ThreatBadge iocValue={row.original.source_ip} />
  )
}

// Or multiple IOCs per alert:
function AlertRow({ alert }) {
  return (
    <tr>
      <td>{alert.source_ip}</td>
      <td><ThreatBadge iocValue={alert.source_ip} /></td>
      <td>{alert.destination_domain}</td>
      <td><ThreatBadge iocValue={alert.destination_domain} /></td>
    </tr>
  );
}
```

### Step 6 — Full Lookup Panel (optional)

For a side panel that shows the full ThreatLens result inline:

```jsx
import { useState } from 'react';
import { enrichIOC, getRiskColor } from '../lib/threatlens';

const THREATLENS_URL = import.meta.env.VITE_THREATLENS_URL || 'http://localhost:8000';

export default function ThreatPanel({ iocValue, onClose }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);

  useState(() => {
    enrichIOC(iocValue).then(setData).finally(() => setLoading(false));
  }, [iocValue]);

  if (loading) return <div>Loading threat intelligence...</div>;
  if (!data)   return <div>Failed to load</div>;

  const { text, bg, border } = getRiskColor(data.risk_level);

  return (
    <div style={{ background: '#0f172a', border: '1px solid #334155',
                  borderRadius: 12, padding: 20, minWidth: 360 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
        <span style={{ color: '#f1f5f9', fontFamily: 'monospace' }}>{data.ioc?.value}</span>
        <button onClick={onClose} style={{ color: '#64748b', background: 'none', border: 'none' }}>✕</button>
      </div>
      <div style={{ background: bg, border: `1px solid ${border}`,
                    borderRadius: 8, padding: 12, textAlign: 'center', marginBottom: 12 }}>
        <div style={{ color: text, fontSize: 28, fontWeight: 700 }}>{data.score?.toFixed(1)}</div>
        <div style={{ color: text, fontSize: 14, textTransform: 'uppercase' }}>{data.risk_level}</div>
        <div style={{ color: '#94a3b8', fontSize: 11 }}>Confidence: {data.confidence}</div>
      </div>
      {/* Score breakdown */}
      {data.breakdown && Object.entries(data.breakdown).map(([src, val]) => (
        <div key={src} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
          <span style={{ color: '#94a3b8', fontSize: 12, textTransform: 'capitalize' }}>{src}</span>
          <span style={{ color: '#e2e8f0', fontSize: 12, fontFamily: 'monospace' }}>{val}</span>
        </div>
      ))}
      {/* MITRE */}
      {data.mitre?.length > 0 && (
        <div style={{ marginTop: 12, padding: '8px 12px',
                      background: '#0c1a2e', borderRadius: 8, border: '1px solid #1e3a5f' }}>
          <div style={{ color: '#7dd3fc', fontSize: 11, marginBottom: 6 }}>MITRE ATT&CK</div>
          {data.mitre.map(t => (
            <div key={t.technique_id} style={{ color: '#e2e8f0', fontSize: 11, marginBottom: 3 }}>
              <span style={{ color: '#f87171', fontFamily: 'monospace' }}>{t.technique_id}</span>
              {' '}{t.technique}
            </div>
          ))}
        </div>
      )}
      {/* Deep link */}
      <a href={`${THREATLENS_URL}/lookup?q=${encodeURIComponent(iocValue)}`}
         target="_blank" rel="noreferrer"
         style={{ display: 'block', marginTop: 12, textAlign: 'center',
                  color: '#38bdf8', fontSize: 12 }}>
        Open in ThreatLens →
      </a>
    </div>
  );
}
```

---

## 6. Frontend Component Integration

### Component Inventory

| Component | File | Props | Purpose |
|---|---|---|---|
| `IOCSearchBar` | `components/IOCSearchBar.jsx` | `onResult(data)` | Search + submit |
| `ThreatScoreGauge` | `components/ThreatScoreGauge.jsx` | `score, riskLevel, confidence, queryTimeMs` | Arc gauge |
| `SourceResultCard` | `components/SourceResultCard.jsx` | `source, data` | Per-API result card |
| `MITREHeatmap` | `components/MITREHeatmap.jsx` | `techniques[]` | ATT&CK grid |
| `AnalystPanel` | `components/AnalystPanel.jsx` | `iocValue, notes[], tags[]` | Notes & tags |
| `ThreatTimeline` | `components/ThreatTimeline.jsx` | `data[]` | Activity area chart |
| `LookupResult` | `components/LookupResult.jsx` | `result, onClose` | Full result wrapper |

### Utility Functions

```javascript
// src/lib/scoring.js
import { getRiskConfig } from './lib/scoring';  // ThreatLens repo

const cfg = getRiskConfig('critical');
// → { color: '#DC2626', label: 'Critical', bg: 'bg-red-900/30', ... }
```

---

## 7. Response Shape Reference

### POST /api/v1/ioc/lookup — Full Response

```typescript
interface LookupResponse {
  source: 'live' | 'cache';
  ioc: {
    value: string;
    type: 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256';
    id: number;
  };
  scan_id: number;
  score: number;              // 0.00 – 100.00
  risk_level: 'clean' | 'low' | 'suspicious' | 'malicious' | 'critical';
  confidence: 'high' | 'medium' | 'low';
  breakdown: {
    virustotal: number;       // contribution out of 32
    abuseipdb:  number;       // contribution out of 25
    alienvault: number;       // contribution out of 22
    urlhaus:    number;       // contribution out of 12
    greynoise:  number;       // contribution out of  9
  };
  mitre: Array<{
    technique_id: string;     // e.g. "T1595"
    technique:    string;     // e.g. "Active Scanning"
    tactic:       string;     // e.g. "reconnaissance"
    confidence:   'high' | 'medium' | 'low';
    source:       string;     // which API triggered this
  }>;
  results: {
    virustotal: VirusTotalResult | null;
    abuseipdb:  AbuseIPDBResult  | null;
    alienvault: AlienVaultResult | null;
    urlhaus:    URLhausResult    | null;
    greynoise:  GreyNoiseResult  | null;
  };
  errors: Array<{ source: string; error: string }>;
  query_time_ms: number;
  notes: Array<{ id: number; note: string; analyst: string; created_at: string }>;
  tags: string[];
}
```

### Source Result Shapes

```typescript
interface VirusTotalResult {
  status: 'found' | 'not_found' | 'no_api_key';
  malicious: number; suspicious: number; harmless: number;
  undetected: number; total: number; tags: string[];
}

interface AbuseIPDBResult {
  status: 'found' | 'no_api_key';
  confidence_score: number;  // 0-100
  total_reports: number; distinct_reporters: number;
  country_code: string; isp: string; is_tor: boolean;
}

interface AlienVaultResult {
  status: 'found' | 'not_found' | 'no_api_key';
  pulse_count: number; tags: string[];
  malware_families: string[]; adversaries: string[];
}

interface URLhausResult {
  status: 'found' | 'not_found';
  url_status: 'online' | 'offline';
  threat: string; tags: string[];
}

interface GreyNoiseResult {
  status: 'found' | 'not_found' | 'no_api_key';
  classification: 'malicious' | 'benign' | 'unknown';
  noise: boolean; riot: boolean; name: string;
}
```

---

## 8. Risk Level → UI Color Mapping

Use these exact colors to match ThreatLens visual language in your SecOps UI:

```javascript
const RISK_COLORS = {
  clean:      { hex: '#16A34A', tailwind: 'text-green-600',  bg: 'bg-green-900/30' },
  low:        { hex: '#2563EB', tailwind: 'text-blue-500',   bg: 'bg-blue-900/30'  },
  suspicious: { hex: '#CA8A04', tailwind: 'text-yellow-600', bg: 'bg-yellow-900/30'},
  malicious:  { hex: '#EA580C', tailwind: 'text-orange-500', bg: 'bg-orange-900/30'},
  critical:   { hex: '#DC2626', tailwind: 'text-red-600',    bg: 'bg-red-900/30'   },
};

// Score thresholds
const RISK_THRESHOLDS = [
  { max: 20,  level: 'clean' },
  { max: 40,  level: 'low' },
  { max: 60,  level: 'suspicious' },
  { max: 80,  level: 'malicious' },
  { max: 101, level: 'critical' },
];
```

---

## 9. Environment & CORS Setup

### ThreatLens Side (.env)

```env
# Add SecOps origin here
CORS_ORIGINS=https://your-secops.replit.app,http://localhost:3000
```

### SecOps Side (.env)

```env
VITE_THREATLENS_URL=https://your-threatlens.replit.app
```

### Files to modify in ThreatLens for CORS

**`backend/app/config.py`** — add:
```python
CORS_ORIGINS: str = "*"
```

**`backend/app/main.py`** — update middleware:
```python
origins = [o.strip() for o in settings.CORS_ORIGINS.split(",")]
app.add_middleware(CORSMiddleware, allow_origins=origins, ...)
```

---

## 10. Common Integration Patterns

### Pattern A — Fire & Forget Badge (lightest)
Best for alert tables with many rows. Click to enrich on demand.
```
Alert row → [Enrich] button → one POST → ThreatBadge renders
```

### Pattern B — Auto-Enrich on Alert Detail (medium)
When analyst opens an alert detail page, auto-enrich all IOCs.
```
Alert detail mount → enrichIOC(source_ip) + enrichIOC(dest_domain) in parallel
                   → render score + MITRE in sidebar
```

### Pattern C — Batch Pre-Enrich (heavy, scheduled)
Nightly job enriches all new IOCs seen in the last 24 hours.
```python
# backend cron job or scheduled function
for alert in todays_alerts:
    for ioc in extract_iocs(alert):
        requests.post(f"{THREATLENS_URL}/api/v1/ioc/lookup", json={"value": ioc})
```

### Pattern D — Alert Auto-Tag from ThreatLens (full integration)
When ThreatLens returns critical/malicious, auto-tag the SecOps alert.
```javascript
const threat = await enrichIOC(alert.source_ip);
if (['malicious', 'critical'].includes(threat.risk_level)) {
  await updateAlert(alert.id, {
    tags: [...alert.tags, `threat:${threat.risk_level}`, 'auto-enriched'],
    priority: 'high',
    threat_score: threat.score,
  });
}
```

---

## Files Modified When Integrating

### In ThreatLens
- `backend/app/config.py` — add `CORS_ORIGINS` setting
- `backend/app/main.py` — read origins from config
- `.env` — add SecOps domain to `CORS_ORIGINS`

### In SecOps Project (new files)
- `src/lib/threatlens.js` — API client + color helpers
- `src/components/ThreatBadge.jsx` — inline score chip
- `src/components/ThreatPanel.jsx` — full detail panel

### In SecOps Project (modified files)
- Alert table component — add ThreatBadge column
- Alert detail page — add ThreatPanel in sidebar
- `.env` — add `VITE_THREATLENS_URL`

---

*ThreatLens Architecture v1.0 — for SecOps Mini SIEM integration*
