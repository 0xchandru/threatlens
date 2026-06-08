<div align="center">

<img src="https://img.shields.io/badge/ThreatLens-SOC%20Intelligence-0ea5e9?style=for-the-badge&logo=shield&logoColor=white" alt="ThreatLens"/>

# 🛡️ ThreatLens
### SOC Threat Intelligence Aggregator

**Query 5 threat intel sources in parallel · Composite scoring · MITRE ATT&CK mapping · PDF reports**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vitejs.dev)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3-38B2AC?style=flat-square&logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

<br/>

![ThreatLens Dashboard Preview](https://img.shields.io/badge/Live%20Demo-Available%20on%20Replit-orange?style=for-the-badge&logo=replit&logoColor=white)

</div>

---

## 🎯 What Makes ThreatLens Different

| Basic IOC Lookup Tool | **ThreatLens** |
|---|---|
| One API, sequential | **5 APIs, parallel async** — ~800ms total |
| Raw JSON dump | **Composite threat score 0–100** with weighted breakdown |
| No context | **MITRE ATT&CK** tactic & technique mapping |
| Stateless | **Full IOC history**, lookup trends, caching |
| No workflow | **Analyst notes, threat tags, case tracking** |
| No deliverable | **Professional PDF reports** for ticket attachments |
| Single IOC | **Batch lookups**, cross-IOC search & filtering |
| No integration | **REST API** for SIEM/SecOps integration |

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Intelligent IOC Detection
Auto-detects and normalizes:
- IPv4 / IPv6 addresses
- Domains and full URLs
- File hashes — MD5, SHA1, SHA256
- Private IP rejection

</td>
<td width="50%">

### ⚡ Parallel Query Engine
All 5 sources fire simultaneously via `asyncio.gather`:
- **VirusTotal** — 70+ AV engine verdicts
- **AbuseIPDB** — Abuse confidence score
- **AlienVault OTX** — Pulse & threat actor data
- **URLhaus** — Active malware distribution
- **GreyNoise** — Internet scanner classification

</td>
</tr>
<tr>
<td width="50%">

### 📊 Composite Threat Scoring
Weighted 0–100 score across all sources:
```
VirusTotal   → 32% weight
AbuseIPDB    → 25% weight
AlienVault   → 22% weight
URLhaus      → 12% weight
GreyNoise    →  9% weight
```
Risk levels: `clean` → `low` → `suspicious` → `malicious` → `critical`

</td>
<td width="50%">

### 🧩 MITRE ATT&CK Mapping
Signal-driven technique detection:
- `T1204.002` Malicious File (VT trojan tags)
- `T1071` Application Layer Protocol (C2)
- `T1046` Network Service Discovery (AbuseIPDB)
- `T1090.003` Multi-hop Proxy (Tor exit nodes)
- `T1566` Phishing (OTX pulse tags)
- `T1595` Active Scanning (GreyNoise)
- `T1105` Ingress Tool Transfer (URLhaus online)

</td>
</tr>
<tr>
<td width="50%">

### 📝 Analyst Workflow
- Add investigation notes with timestamps
- Tag IOCs (`c2`, `ransomware`, `phishing`, etc.)
- Full scan history & score trend
- Background IP enrichment (ASN, country, rDNS)

</td>
<td width="50%">

### 📄 PDF Report Generation
Professional reports via ReportLab:
- IOC summary with risk level
- Score breakdown by source
- MITRE ATT&CK table
- Analyst notes included
- Attachable to tickets / cases

</td>
</tr>
</table>

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser / SecOps SIEM                    │
│                   React 18 + Vite  (port 5000)                  │
│  Dashboard │ IOC Lookup │ Search │ Reports │ Analyst Panel       │
└───────────────────────┬─────────────────────────────────────────┘
                        │  Vite proxy  /api → localhost:8000
┌───────────────────────▼─────────────────────────────────────────┐
│                    FastAPI Backend  (port 8000)                  │
│                                                                  │
│  POST /api/v1/ioc/lookup       ←── IOC submission               │
│  GET  /api/v1/ioc/{value}      ←── Detail + enrichment          │
│  GET  /api/v1/ioc/{value}/history                                │
│  POST /api/v1/ioc/{value}/notes                                  │
│  PUT  /api/v1/ioc/{value}/tags                                   │
│  GET  /api/v1/dashboard/stats                                    │
│  GET  /api/v1/dashboard/timeline                                 │
│  GET  /api/v1/search                                             │
│  POST /api/v1/reports/generate                                   │
│  GET  /api/v1/reports/{id}/download                              │
└──────────┬────────────┬──────────────────────────────────────────┘
           │            │
    ┌──────▼──────┐  ┌──▼────────────────────────────────────────┐
    │ PostgreSQL  │  │      Async Parallel Query Engine           │
    │  (Replit)   │  │                                            │
    │  iocs       │  │  VirusTotal ──┐                            │
    │  scans      │  │  AbuseIPDB   ├──► asyncio.gather()        │
    │  mitre_maps │  │  AlienVault  │     ~800ms total            │
    │  notes      │  │  URLhaus ────┤                            │
    │  tags       │  │  GreyNoise ──┘                            │
    │  enrichment │  │                                            │
    │  reports    │  │  Scorer → MITRE Mapper → DB Persist       │
    └─────────────┘  └────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 20+
- PostgreSQL (or SQLite for dev)

### 1. Clone & Install

```bash
git clone https://github.com/0xchandru/threatlens.git
cd threatlens

# Backend
cd backend
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your API keys (all optional)
```

### 3. Run Development Servers

```bash
# Terminal 1 — Backend API
cd backend
uvicorn app.main:app --host localhost --port 8000 --reload

# Terminal 2 — Frontend
cd frontend
npm run dev
```

Open **http://localhost:5000**

### 4. Or — Single Command

```bash
bash start.sh
```

---

## 🔑 API Keys Setup

All keys are **optional** — the app returns graceful `no_api_key` responses and still works end-to-end. For live intel, register for free tiers:

| Source | Free Tier | Rate Limit | Registration |
|---|---|---|---|
| VirusTotal | ✅ Free | 4 req/min | [virustotal.com](https://virustotal.com) |
| AbuseIPDB | ✅ Free | 1,000/day | [abuseipdb.com](https://abuseipdb.com) |
| AlienVault OTX | ✅ Free | No hard limit | [otx.alienvault.com](https://otx.alienvault.com) |
| URLhaus | ✅ Free | No key needed | Built-in |
| GreyNoise | ✅ Community | 1,000/day | [greynoise.io](https://greynoise.io) |

Set keys in `.env` or as environment/Replit secrets:

```env
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
ALIENVAULT_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here
```

---

## 📡 REST API Reference

Base URL: `http://localhost:8000/api/v1`

### IOC Lookup

```http
POST /api/v1/ioc/lookup
Content-Type: application/json

{ "value": "1.2.3.4" }
```

**Response:**
```json
{
  "source": "live",
  "ioc": { "value": "1.2.3.4", "type": "ip", "id": 1 },
  "scan_id": 42,
  "score": 87.5,
  "risk_level": "critical",
  "confidence": "high",
  "breakdown": {
    "virustotal": 28.3,
    "abuseipdb": 24.5,
    "alienvault": 19.8,
    "urlhaus": 9.6,
    "greynoise": 5.3
  },
  "mitre": [
    {
      "technique_id": "T1595",
      "technique": "Active Scanning",
      "tactic": "reconnaissance",
      "confidence": "high",
      "source": "greynoise"
    }
  ],
  "results": { "virustotal": {...}, "abuseipdb": {...}, ... },
  "errors": [],
  "query_time_ms": 823
}
```

### Quick Enrich (for SecOps Alert Integration)

```http
POST /api/v1/ioc/lookup
Content-Type: application/json

{ "value": "suspicious-domain.com" }
```

Returns cached results if queried within the last 60 minutes — ideal for high-volume SIEM alert enrichment.

### IOC Detail & History

```http
GET /api/v1/ioc/{ioc_value}
GET /api/v1/ioc/{ioc_value}/history
```

### Dashboard Stats

```http
GET /api/v1/dashboard/stats
GET /api/v1/dashboard/timeline?days=30
```

### Search & Filter

```http
GET /api/v1/search?tag=c2&risk_level=critical&ioc_type=ip&limit=50
```

### Analyst Notes & Tags

```http
POST /api/v1/ioc/{value}/notes
Body: { "note": "Confirmed C2 — block at firewall", "analyst": "analyst1" }

PUT /api/v1/ioc/{value}/tags
Body: { "tags": ["c2", "ransomware", "confirmed"] }
```

### PDF Report

```http
POST /api/v1/reports/generate
Body: { "ioc_value": "1.2.3.4", "scan_id": 42 }

GET  /api/v1/reports/{report_id}/download
```

---

## 🔌 SecOps SIEM Integration

ThreatLens exposes a simple REST API designed to be called from any SIEM, SOAR, or custom alert dashboard.

### JavaScript / Fetch

```javascript
async function enrichAlert(iocValue) {
  const response = await fetch('https://your-threatlens.replit.app/api/v1/ioc/lookup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ value: iocValue })
  });
  return response.json();
}

// Use in alert row
const threat = await enrichAlert(alert.source_ip);
console.log(`Score: ${threat.score} | Risk: ${threat.risk_level}`);
```

### Python / Requests

```python
import requests

THREATLENS_URL = "https://your-threatlens.replit.app"

def enrich_ioc(value: str) -> dict:
    resp = requests.post(
        f"{THREATLENS_URL}/api/v1/ioc/lookup",
        json={"value": value},
        timeout=30
    )
    resp.raise_for_status()
    return resp.json()

# In your alert processing pipeline
threat = enrich_ioc("185.220.101.47")
if threat["risk_level"] in ("malicious", "critical"):
    escalate_alert(alert_id, threat)
```

### CORS Configuration

To allow your SecOps project to call ThreatLens cross-origin, set in `.env`:

```env
CORS_ORIGINS=https://your-secops.replit.app,http://localhost:3000
```

---

## 📁 Project Structure

```
threatlens/
├── backend/
│   └── app/
│       ├── main.py              # FastAPI app + CORS + static serving
│       ├── config.py            # pydantic-settings (reads .env)
│       ├── database.py          # SQLAlchemy engine + session
│       ├── crud.py              # All database operations
│       ├── api/v1/
│       │   ├── ioc.py           # Lookup, history, notes, tags
│       │   ├── dashboard.py     # Stats + timeline
│       │   ├── search.py        # Cross-IOC filtering
│       │   └── reports.py       # PDF generation + download
│       ├── services/
│       │   ├── normalizer.py    # IOC type detection (IP/domain/hash/URL)
│       │   ├── aggregator.py    # Async parallel query engine
│       │   ├── scorer.py        # Weighted composite scoring (0–100)
│       │   ├── mitre.py         # ATT&CK technique mapping rules
│       │   ├── enricher.py      # WHOIS / ASN / geo (background task)
│       │   └── pdf_generator.py # ReportLab PDF builder
│       ├── integrations/
│       │   ├── virustotal.py
│       │   ├── abuseipdb.py
│       │   ├── alienvault.py
│       │   ├── urlhaus.py
│       │   └── greynoise.py
│       └── models/
│           ├── ioc.py           # IOC + IOCType enum
│           ├── scan.py          # Scan + MITREMapping
│           ├── analyst.py       # Notes + Tags + Enrichment
│           └── report.py        # Stored PDF reports
├── frontend/
│   └── src/
│       ├── pages/               # Dashboard, LookupPage, SearchPage, ReportsPage
│       ├── components/          # IOCSearchBar, ThreatScoreGauge, MITREHeatmap...
│       └── lib/                 # api.js (axios), scoring.js (risk colors)
├── .env.example                 # ← Start here
├── start.sh                     # Single-command dev launcher
└── README.md
```

---

## 🗄️ Database Schema

```sql
iocs              — Unique IOC records (value, type, first_seen, lookup_count)
scans             — Each lookup result (score, risk_level, raw_results JSON)
mitre_mappings    — ATT&CK techniques mapped per scan
analyst_notes     — Free-text investigation notes
threat_tags       — Analyst-applied labels per IOC
enrichment_data   — ASN, country, city, rDNS per IP
reports           — Stored PDF bytes with metadata
```

---

## 🧠 Scoring Algorithm

The composite score weights each source by its reliability and coverage:

```
Score = Σ (source_signal × source_weight)

VirusTotal  (32%): ratio of malicious/suspicious engines to total
AbuseIPDB   (25%): abuse confidence score (0–100%) linearly mapped
AlienVault  (22%): sigmoid-like pulse count (0 pulses=0, 15+=max)
URLhaus     (12%): online=full weight, historical=40% weight
GreyNoise   ( 9%): malicious=full, RIOT=0, unknown=30%

Confidence:
  high   → ≥80% of total source weight returned data
  medium → 45–80%
  low    → <45%
```

---

## 🔒 Security Notes

- All API keys are read from environment variables — never hardcoded
- Private IP addresses are rejected (RFC 1918 / loopback)
- CORS is configurable via `CORS_ORIGINS` environment variable
- JWT secret must be rotated in production
- PDF reports are stored in the database (not filesystem)
- No authentication by default — add your SIEM's token or API key header for production

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Backend | Python 3.11 + FastAPI | Async REST API |
| HTTP Client | aiohttp | True async parallel requests |
| ORM | SQLAlchemy 2.0 | Works with SQLite + PostgreSQL |
| Validation | Pydantic v2 | IOC schema enforcement |
| PDF | ReportLab | Programmatic report generation |
| Frontend | React 18 + Vite | SPA dev server |
| State | TanStack Query v5 | Cache + background refetch |
| Charts | Recharts | Risk distribution, timeline |
| Styling | Tailwind CSS | SOC dark theme |
| Database | PostgreSQL (prod) / SQLite (dev) | Persistent storage |

---

## 🎤 Portfolio Talking Points

**"Why parallel async querying?"**
> Sequential calls to 5 APIs take 5–15 seconds. With `asyncio.gather`, all 5 fire simultaneously. Average lookup: ~800ms — the speed SOC analysts need when triaging hundreds of alerts per shift.

**"How did you design the scoring algorithm?"**
> Weighted by source strength: VirusTotal covers 70+ AV engines (highest weight), AbuseIPDB specializes in IP abuse, OTX adds threat actor attribution. The confidence metric tells the analyst how much data backed the score.

**"What does the MITRE mapping add?"**
> Raw data says "malicious". MITRE says "this is Active Scanning + C2" — which determines the SOC response: block at perimeter, escalate to IR, or user education.

---

## 📜 License

MIT — free to use for portfolio, learning, and production projects.

---

<div align="center">

Built for SOC analysts · Powered by open threat intelligence · Made with ❤️

**[Live Demo](https://replit.com) · [API Docs](http://localhost:8000/docs) · [Blueprint](Threatlens_Blueprint.md)**

</div>
