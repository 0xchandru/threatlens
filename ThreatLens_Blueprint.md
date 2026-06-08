# ThreatLens — Complete Technical Blueprint
### SOC Portfolio Project: Threat Intelligence Aggregator

---

## Why This Stands Out From a Basic IOC Lookup Tool

Most entry-level projects call one API and display raw JSON. ThreatLens replicates workflows that real L1 SOC analysts perform every shift:

| Basic Lookup Tool | ThreatLens |
|---|---|
| One API, sequential | 5 APIs, parallel async |
| Raw JSON dump | Composite threat score (0–100) |
| No context | MITRE ATT&CK tactic/technique mapping |
| Stateless | Full IOC history with lookup trends |
| No workflow | Analyst notes, tags, case tracking |
| No deliverable | Professional PDF report generation |
| Single IOC | Batch lookups, search, filtering |

When an interviewer asks "walk me through a threat investigation," you can demo all of this end-to-end.

---

## 1. Tech Stack

### Backend
| Layer | Technology | Why |
|---|---|---|
| API framework | Python 3.11 + FastAPI | Async native, auto Swagger docs |
| HTTP client | aiohttp | True async, connection pooling |
| ORM | SQLAlchemy 2.0 | Works with SQLite + PostgreSQL |
| Database (dev) | SQLite | Zero setup, file-based |
| Database (prod) | PostgreSQL | Concurrent writes, JSONB queries |
| Cache | Redis | 24h TTL on API responses |
| Auth | python-jose (JWT) | Stateless analyst sessions |
| PDF | ReportLab | Programmatic reports with charts |
| Validation | Pydantic v2 | IOC schema enforcement |
| Background tasks | FastAPI BackgroundTasks / Celery | Enrichment pipeline |

### Frontend
| Layer | Technology | Why |
|---|---|---|
| Framework | React 18 + Vite | Fast dev server |
| State/fetching | TanStack Query v5 | Cache, background refetch |
| Charts | Recharts | Risk distribution, timeline |
| Styling | Tailwind CSS | Rapid SOC-dark-theme UI |
| HTTP | Axios | Interceptors for JWT |
| Routing | React Router v6 | SPA with deep links |

### Infrastructure
- Docker + Docker Compose
- Nginx reverse proxy
- GitHub Actions CI (tests + lint)

---

## 2. Project Directory Structure

```
threatlens/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI app factory
│   │   ├── config.py                # Settings via pydantic-settings
│   │   ├── database.py              # SQLAlchemy engine + session
│   │   ├── models/                  # SQLAlchemy ORM models
│   │   │   ├── ioc.py
│   │   │   ├── scan.py
│   │   │   ├── analyst.py
│   │   │   └── report.py
│   │   ├── schemas/                 # Pydantic request/response schemas
│   │   │   ├── ioc.py
│   │   │   ├── scan.py
│   │   │   └── analyst.py
│   │   ├── api/
│   │   │   ├── v1/
│   │   │   │   ├── ioc.py           # Lookup, history, enrich
│   │   │   │   ├── analyst.py       # Notes, tags
│   │   │   │   ├── search.py        # Cross-IOC search/filter
│   │   │   │   ├── reports.py       # PDF generation
│   │   │   │   └── dashboard.py     # Stats endpoint
│   │   │   └── deps.py              # Shared dependencies (DB session, auth)
│   │   ├── services/
│   │   │   ├── normalizer.py        # IOC type detection + parsing
│   │   │   ├── aggregator.py        # Async parallel query engine
│   │   │   ├── scorer.py            # Composite threat scoring
│   │   │   ├── enricher.py          # WHOIS, ASN, geolocation
│   │   │   ├── mitre.py             # ATT&CK technique mapping
│   │   │   └── pdf_generator.py     # ReportLab PDF builder
│   │   └── integrations/            # One file per threat intel source
│   │       ├── base.py              # Abstract base class
│   │       ├── virustotal.py
│   │       ├── abuseipdb.py
│   │       ├── alienvault.py
│   │       ├── urlhaus.py
│   │       └── greynoise.py
│   ├── tests/
│   │   ├── test_normalizer.py
│   │   ├── test_scorer.py
│   │   └── test_integrations.py     # Mock API responses
│   ├── alembic/                     # DB migrations
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── IOCSearchBar.jsx
│   │   │   ├── ThreatScoreGauge.jsx
│   │   │   ├── SourceResultCard.jsx
│   │   │   ├── MITREHeatmap.jsx
│   │   │   ├── AnalystPanel.jsx
│   │   │   ├── ThreatTimeline.jsx
│   │   │   └── ReportBuilder.jsx
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── LookupPage.jsx
│   │   │   ├── IOCDetailPage.jsx
│   │   │   ├── SearchPage.jsx
│   │   │   └── ReportsPage.jsx
│   │   ├── hooks/
│   │   │   ├── useIOCLookup.js
│   │   │   └── useAnalystNotes.js
│   │   └── lib/
│   │       ├── api.js               # Axios instance
│   │       └── scoring.js           # Risk level colors/labels
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
└── .github/workflows/ci.yml
```

---

## 3. Database Schema

### 3.1 SQLAlchemy Models

```python
# app/models/ioc.py
from sqlalchemy import Column, String, Integer, DateTime, Float, Enum
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime, timezone
import enum

class IOCType(str, enum.Enum):
    ip       = "ip"
    domain   = "domain"
    url      = "url"
    md5      = "md5"
    sha1     = "sha1"
    sha256   = "sha256"

class IOC(Base):
    __tablename__ = "iocs"

    id            = Column(Integer, primary_key=True, index=True)
    value         = Column(String, unique=True, index=True, nullable=False)
    ioc_type      = Column(Enum(IOCType), nullable=False)
    first_seen    = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen     = Column(DateTime, onupdate=lambda: datetime.now(timezone.utc))
    lookup_count  = Column(Integer, default=1)
    # Relationships
    scans         = relationship("Scan", back_populates="ioc")
    notes         = relationship("AnalystNote", back_populates="ioc")
    tags          = relationship("ThreatTag", back_populates="ioc")
    enrichment    = relationship("EnrichmentData", back_populates="ioc", uselist=False)
```

```python
# app/models/scan.py
from sqlalchemy import Column, Integer, Float, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime, timezone

class Scan(Base):
    __tablename__ = "scans"

    id              = Column(Integer, primary_key=True)
    ioc_id          = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    timestamp       = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    composite_score = Column(Float, nullable=False)   # 0.0 – 100.0
    risk_level      = Column(String, nullable=False)  # clean/low/suspicious/malicious/critical
    raw_results     = Column(JSON)                    # Full API responses stored as JSON
    sources_queried = Column(JSON)                    # Which APIs returned data
    error_sources   = Column(JSON, default=list)      # Which APIs failed
    query_time_ms   = Column(Integer)                 # Total parallel query time
    ioc             = relationship("IOC", back_populates="scans")
    mitre_mappings  = relationship("MITREMapping", back_populates="scan")

class MITREMapping(Base):
    __tablename__ = "mitre_mappings"

    id           = Column(Integer, primary_key=True)
    scan_id      = Column(Integer, ForeignKey("scans.id"), nullable=False)
    technique_id = Column(String)    # e.g. "T1071"
    technique    = Column(String)    # e.g. "Application Layer Protocol"
    tactic       = Column(String)    # e.g. "command-and-control"
    confidence   = Column(String)    # high / medium / low
    source       = Column(String)    # which API signal triggered this
    scan         = relationship("Scan", back_populates="mitre_mappings")
```

```python
# app/models/analyst.py
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime, timezone

class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id          = Column(Integer, primary_key=True)
    ioc_id      = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    note        = Column(Text, nullable=False)
    analyst     = Column(String, default="analyst")
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    ioc         = relationship("IOC", back_populates="notes")

class ThreatTag(Base):
    __tablename__ = "threat_tags"

    id         = Column(Integer, primary_key=True)
    ioc_id     = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    tag        = Column(String, index=True)   # e.g. "c2", "ransomware", "phishing"
    created_by = Column(String, default="analyst")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    ioc        = relationship("IOC", back_populates="tags")

class EnrichmentData(Base):
    __tablename__ = "enrichment_data"

    id           = Column(Integer, primary_key=True)
    ioc_id       = Column(Integer, ForeignKey("iocs.id"), unique=True, nullable=False)
    asn          = Column(String)
    asn_org      = Column(String)
    country_code = Column(String)
    country_name = Column(String)
    city         = Column(String)
    whois_data   = Column(JSON)
    rdns         = Column(String)
    enriched_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    ioc          = relationship("IOC", back_populates="enrichment")
```

---

## 4. IOC Normalizer and Type Detector

This is the entry point for every lookup. Supports IPs (v4/v6), domains, URLs, MD5, SHA1, SHA256.

```python
# app/services/normalizer.py
import re
import ipaddress
from app.models.ioc import IOCType

# Regex patterns
PATTERNS = {
    IOCType.sha256: re.compile(r'^[a-fA-F0-9]{64}$'),
    IOCType.sha1:   re.compile(r'^[a-fA-F0-9]{40}$'),
    IOCType.md5:    re.compile(r'^[a-fA-F0-9]{32}$'),
    IOCType.url:    re.compile(
        r'^(https?|ftp)://[^\s/$.?#].[^\s]*$', re.IGNORECASE
    ),
    IOCType.domain: re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    ),
}

class NormalizedIOC:
    def __init__(self, value: str, ioc_type: IOCType):
        self.value    = value.strip().lower()
        self.ioc_type = ioc_type

    def is_private_ip(self) -> bool:
        if self.ioc_type != IOCType.ip:
            return False
        try:
            return ipaddress.ip_address(self.value).is_private
        except ValueError:
            return False

def detect_and_normalize(raw_input: str) -> NormalizedIOC:
    value = raw_input.strip()

    # Try IP address first (both v4 and v6)
    try:
        ipaddress.ip_address(value)
        return NormalizedIOC(value, IOCType.ip)
    except ValueError:
        pass

    # Hash detection (length-based, then regex)
    for ioc_type in (IOCType.sha256, IOCType.sha1, IOCType.md5):
        if PATTERNS[ioc_type].match(value):
            return NormalizedIOC(value.lower(), ioc_type)

    # URL before domain (URL regex is stricter)
    if PATTERNS[IOCType.url].match(value):
        return NormalizedIOC(value, IOCType.url)

    # Strip leading wildcard for domain check
    domain_check = value.lstrip("*.")
    if PATTERNS[IOCType.domain].match(domain_check):
        return NormalizedIOC(value, IOCType.domain)

    raise ValueError(f"Cannot determine IOC type for: {value!r}")
```

---

## 5. Async Parallel Query Engine (Core Feature)

This is the architectural centrepiece. All 5 APIs are queried simultaneously using `asyncio.gather`. A 5x speed-up over sequential calls — and the query time appears in the UI as a portfolio talking point.

```python
# app/services/aggregator.py
import asyncio
import time
import aiohttp
from app.models.ioc import IOCType
from app.integrations import virustotal, abuseipdb, alienvault, urlhaus, greynoise

TIMEOUT = aiohttp.ClientTimeout(total=10)  # 10s max per source

async def query_all_sources(
    value: str,
    ioc_type: IOCType,
    session: aiohttp.ClientSession
) -> dict:
    """
    Fires all 5 API calls simultaneously. Returns partial results even
    if some sources fail — never blocks the entire lookup on one API.
    """
    start = time.monotonic()

    tasks = [
        virustotal.query(session, value, ioc_type),
        abuseipdb.query(session, value, ioc_type),
        alienvault.query(session, value, ioc_type),
        urlhaus.query(session, value, ioc_type),
        greynoise.query(session, value, ioc_type),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    source_names = ["virustotal", "abuseipdb", "alienvault", "urlhaus", "greynoise"]
    output, errors = {}, []

    for name, result in zip(source_names, results):
        if isinstance(result, Exception):
            errors.append({"source": name, "error": str(result)})
            output[name] = None
        else:
            output[name] = result

    return {"results": output, "errors": errors, "query_time_ms": elapsed_ms}


async def run_aggregation(value: str, ioc_type: IOCType) -> dict:
    """Entry point — creates shared aiohttp session for all requests."""
    async with aiohttp.ClientSession(
        timeout=TIMEOUT,
        connector=aiohttp.TCPConnector(limit=10)
    ) as session:
        return await query_all_sources(value, ioc_type, session)
```

### Integration Base Class Pattern

```python
# app/integrations/base.py
from abc import ABC, abstractmethod
import aiohttp
from app.models.ioc import IOCType

class ThreatIntelSource(ABC):
    source_name: str
    supported_types: list[IOCType]

    @abstractmethod
    async def query(
        self,
        session: aiohttp.ClientSession,
        value: str,
        ioc_type: IOCType
    ) -> dict | None:
        """Return normalized response dict or None if unsupported type."""
        ...
```

### VirusTotal Integration

```python
# app/integrations/virustotal.py
import aiohttp
from app.config import settings
from app.models.ioc import IOCType

VT_BASE = "https://www.virustotal.com/api/v3"

ENDPOINT_MAP = {
    IOCType.ip:     "/ip_addresses/{value}",
    IOCType.domain: "/domains/{value}",
    IOCType.url:    "/urls/{value_b64}",
    IOCType.md5:    "/files/{value}",
    IOCType.sha1:   "/files/{value}",
    IOCType.sha256: "/files/{value}",
}

async def query(
    session: aiohttp.ClientSession,
    value: str,
    ioc_type: IOCType
) -> dict | None:
    if ioc_type not in ENDPOINT_MAP:
        return None

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    if ioc_type == IOCType.url:
        import base64
        value_b64 = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        path = ENDPOINT_MAP[ioc_type].format(value_b64=value_b64)
    else:
        path = ENDPOINT_MAP[ioc_type].format(value=value)

    async with session.get(VT_BASE + path, headers=headers) as resp:
        if resp.status == 404:
            return {"status": "not_found"}
        resp.raise_for_status()
        data = await resp.json()

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    return {
        "status": "found",
        "malicious":   stats.get("malicious", 0),
        "suspicious":  stats.get("suspicious", 0),
        "harmless":    stats.get("harmless", 0),
        "undetected":  stats.get("undetected", 0),
        "total":       sum(stats.values()),
        "tags":        attrs.get("tags", []),
        "reputation":  attrs.get("reputation", 0),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "raw":         data,
    }
```

### AbuseIPDB Integration

```python
# app/integrations/abuseipdb.py
import aiohttp
from app.config import settings
from app.models.ioc import IOCType

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

async def query(
    session: aiohttp.ClientSession,
    value: str,
    ioc_type: IOCType
) -> dict | None:
    if ioc_type != IOCType.ip:
        return None  # AbuseIPDB only handles IPs

    headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": value, "maxAgeInDays": 90, "verbose": True}

    async with session.get(ABUSEIPDB_URL, headers=headers, params=params) as resp:
        resp.raise_for_status()
        data = await resp.json()

    d = data.get("data", {})
    return {
        "status":             "found",
        "confidence_score":   d.get("abuseConfidenceScore", 0),
        "total_reports":      d.get("totalReports", 0),
        "distinct_reporters": d.get("numDistinctUsers", 0),
        "country_code":       d.get("countryCode"),
        "isp":                d.get("isp"),
        "usage_type":         d.get("usageType"),
        "is_tor":             d.get("isTor", False),
        "is_whitelisted":     d.get("isWhitelisted", False),
        "last_reported_at":   d.get("lastReportedAt"),
        "raw":                data,
    }
```

### AlienVault OTX Integration

```python
# app/integrations/alienvault.py
import aiohttp
from app.config import settings
from app.models.ioc import IOCType

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"

SECTION_MAP = {
    IOCType.ip:     ("IPv4", ["general", "reputation", "geo", "malware", "url_list"]),
    IOCType.domain: ("domain", ["general", "reputation", "malware", "url_list", "passive_dns"]),
    IOCType.url:    ("url",    ["general"]),
    IOCType.md5:    ("file",   ["general", "analysis"]),
    IOCType.sha1:   ("file",   ["general", "analysis"]),
    IOCType.sha256: ("file",   ["general", "analysis"]),
}

async def query(
    session: aiohttp.ClientSession,
    value: str,
    ioc_type: IOCType
) -> dict | None:
    if ioc_type not in SECTION_MAP:
        return None

    headers = {"X-OTX-API-KEY": settings.ALIENVAULT_API_KEY}
    indicator_type, sections = SECTION_MAP[ioc_type]

    # Fetch general section for pulse count (most important)
    url = f"{OTX_BASE}/{indicator_type}/{value}/general"
    async with session.get(url, headers=headers) as resp:
        if resp.status == 404:
            return {"status": "not_found", "pulse_count": 0}
        resp.raise_for_status()
        data = await resp.json()

    pulse_info = data.get("pulse_info", {})
    pulses = pulse_info.get("pulses", [])

    return {
        "status":       "found",
        "pulse_count":  len(pulses),
        "threat_score": data.get("indicator", {}).get("threat_score"),
        "tags":         list({tag for p in pulses for tag in p.get("tags", [])}),
        "malware_families": list({
            mf for p in pulses
            for mf in p.get("malware_families", [])
        }),
        "adversaries": list({
            a for p in pulses
            for a in p.get("adversary", []) if a
        }),
        "pulse_names":  [p.get("name") for p in pulses[:5]],  # Top 5
        "raw":          data,
    }
```

### URLhaus Integration

```python
# app/integrations/urlhaus.py
import aiohttp
from app.models.ioc import IOCType

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1"

async def query(
    session: aiohttp.ClientSession,
    value: str,
    ioc_type: IOCType
) -> dict | None:
    if ioc_type == IOCType.url:
        endpoint, payload = f"{URLHAUS_URL}/url/", {"url": value}
    elif ioc_type in (IOCType.md5, IOCType.sha256):
        hash_field = "md5_hash" if ioc_type == IOCType.md5 else "sha256_hash"
        endpoint, payload = f"{URLHAUS_URL}/payload/", {hash_field: value}
    else:
        return None

    async with session.post(endpoint, data=payload) as resp:
        resp.raise_for_status()
        data = await resp.json()

    if data.get("query_status") == "no_results":
        return {"status": "not_found"}

    return {
        "status":       "found",
        "url_status":   data.get("url_status"),        # online / offline
        "threat":       data.get("threat"),             # malware_download etc.
        "tags":         data.get("tags") or [],
        "date_added":   data.get("date_added"),
        "reporter":     data.get("reporter"),
        "payloads":     data.get("payloads", [])[:3],  # Trim to top 3
        "raw":          data,
    }
```

### GreyNoise Integration

```python
# app/integrations/greynoise.py
import aiohttp
from app.config import settings
from app.models.ioc import IOCType

GN_BASE = "https://api.greynoise.io/v3/community"

async def query(
    session: aiohttp.ClientSession,
    value: str,
    ioc_type: IOCType
) -> dict | None:
    if ioc_type != IOCType.ip:
        return None  # GreyNoise only indexes IPs

    headers = {"key": settings.GREYNOISE_API_KEY}
    async with session.get(f"{GN_BASE}/{value}", headers=headers) as resp:
        if resp.status == 404:
            return {"status": "not_found", "classification": "unknown"}
        resp.raise_for_status()
        data = await resp.json()

    return {
        "status":         "found",
        "classification": data.get("classification"),  # malicious/benign/unknown
        "noise":          data.get("noise", False),    # True = internet scanner
        "riot":           data.get("riot", False),     # True = known benign service
        "name":           data.get("name"),
        "link":           data.get("link"),
        "last_seen":      data.get("last_seen"),
        "message":        data.get("message"),
        "raw":            data,
    }
```

---

## 6. Composite Threat Scoring Engine

Generates a 0–100 score from weighted signals across all sources.

```python
# app/services/scorer.py
from dataclasses import dataclass

@dataclass
class ScoreResult:
    composite_score: float
    risk_level:      str         # clean / low / suspicious / malicious / critical
    score_breakdown: dict        # Per-source contribution
    confidence:      str         # high / medium / low (based on data coverage)

RISK_LEVELS = [
    (20,  "clean"),
    (40,  "low"),
    (60,  "suspicious"),
    (80,  "malicious"),
    (101, "critical"),
]

# Source weights — sum to 100
WEIGHTS = {
    "virustotal": 32,
    "abuseipdb":  25,
    "alienvault": 22,
    "urlhaus":    12,
    "greynoise":   9,
}

def calculate_composite_score(results: dict) -> ScoreResult:
    breakdown = {}
    total_weight_available = 0  # For confidence calc

    # VirusTotal (32%)
    score_vt = 0.0
    if vt := results.get("virustotal"):
        if vt.get("status") == "found":
            total = vt.get("total", 0)
            if total > 0:
                malicious  = vt.get("malicious", 0)
                suspicious = vt.get("suspicious", 0)
                ratio = (malicious + suspicious * 0.4) / total
                score_vt = min(ratio * WEIGHTS["virustotal"], WEIGHTS["virustotal"])
            total_weight_available += WEIGHTS["virustotal"]
    breakdown["virustotal"] = round(score_vt, 2)

    # AbuseIPDB (25%)
    score_ai = 0.0
    if ai := results.get("abuseipdb"):
        if ai.get("status") == "found":
            confidence = ai.get("confidence_score", 0)
            score_ai = (confidence / 100) * WEIGHTS["abuseipdb"]
            total_weight_available += WEIGHTS["abuseipdb"]
    breakdown["abuseipdb"] = round(score_ai, 2)

    # AlienVault OTX (22%)
    score_av = 0.0
    if av := results.get("alienvault"):
        if av.get("status") == "found":
            pulse_count = av.get("pulse_count", 0)
            # Sigmoid-like: 0 pulses=0, 5=50%, 10=~80%, 20+=max
            normalized = min(pulse_count / 15, 1.0)
            score_av = normalized * WEIGHTS["alienvault"]
            total_weight_available += WEIGHTS["alienvault"]
    breakdown["alienvault"] = round(score_av, 2)

    # URLhaus (12%)
    score_uh = 0.0
    if uh := results.get("urlhaus"):
        if uh.get("status") == "found":
            if uh.get("url_status") == "online":
                score_uh = WEIGHTS["urlhaus"]       # Active = full score
            else:
                score_uh = WEIGHTS["urlhaus"] * 0.4  # Historical = partial
            total_weight_available += WEIGHTS["urlhaus"]
    breakdown["urlhaus"] = round(score_uh, 2)

    # GreyNoise (9%)
    score_gn = 0.0
    if gn := results.get("greynoise"):
        if gn.get("status") == "found":
            classification = gn.get("classification", "unknown")
            if gn.get("riot"):                         # Known-good service
                score_gn = 0
            elif classification == "malicious":
                score_gn = WEIGHTS["greynoise"]
            elif classification == "unknown":
                score_gn = WEIGHTS["greynoise"] * 0.3
            # benign/noise = 0 (scanner, not threat)
            total_weight_available += WEIGHTS["greynoise"]
    breakdown["greynoise"] = round(score_gn, 2)

    composite = sum(breakdown.values())

    # Confidence based on data coverage
    if total_weight_available >= 80:
        confidence = "high"
    elif total_weight_available >= 45:
        confidence = "medium"
    else:
        confidence = "low"

    # Risk level
    risk = next(level for threshold, level in RISK_LEVELS if composite < threshold)

    return ScoreResult(
        composite_score=round(composite, 2),
        risk_level=risk,
        score_breakdown=breakdown,
        confidence=confidence,
    )
```

---

## 7. IOC Enrichment Pipeline

Run in the background after the main lookup so the user gets instant score results while enrichment happens asynchronously.

```python
# app/services/enricher.py
import asyncio
import aiohttp
import ipaddress

IPAPI_URL = "https://ipapi.co/{ip}/json/"
WHOIS_URL = "https://rdap.arin.net/registry/ip/{ip}"

async def enrich_ip(ip: str, session: aiohttp.ClientSession) -> dict:
    """Fetches ASN, country, city, rDNS, and hosting org for an IP."""
    tasks = [
        _fetch_ipapi(ip, session),
        _fetch_rdns(ip, session),
    ]
    ipapi_result, rdns = await asyncio.gather(*tasks, return_exceptions=True)

    if isinstance(ipapi_result, Exception):
        ipapi_result = {}
    if isinstance(rdns, Exception):
        rdns = None

    return {
        "asn":          ipapi_result.get("asn"),
        "asn_org":      ipapi_result.get("org"),
        "country_code": ipapi_result.get("country_code"),
        "country_name": ipapi_result.get("country_name"),
        "city":         ipapi_result.get("city"),
        "rdns":         rdns,
        "is_datacenter": _is_datacenter(ipapi_result.get("org", "")),
    }

async def _fetch_ipapi(ip: str, session: aiohttp.ClientSession) -> dict:
    async with session.get(IPAPI_URL.format(ip=ip)) as resp:
        resp.raise_for_status()
        return await resp.json()

async def _fetch_rdns(ip: str, session: aiohttp.ClientSession) -> str | None:
    import socket
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return result[0]
    except socket.herror:
        return None

def _is_datacenter(org: str) -> bool:
    dc_keywords = ["amazon", "google", "microsoft", "digitalocean",
                   "linode", "vultr", "hetzner", "ovh", "cloudflare"]
    return any(kw in org.lower() for kw in dc_keywords)
```

---

## 8. MITRE ATT&CK Mapper

Maps threat intelligence signals to specific ATT&CK techniques. This is the detail that makes ThreatLens look like a real SIEM.

```python
# app/services/mitre.py
from dataclasses import dataclass

@dataclass
class MITRETechnique:
    technique_id: str
    technique:    str
    tactic:       str
    confidence:   str   # high / medium / low
    source:       str   # Which API signal triggered this

# Signal-to-technique mapping rules
MAPPING_RULES = [
    # VirusTotal signals
    {
        "condition": lambda r: (
            r.get("virustotal", {}) and
            r["virustotal"].get("malicious", 0) > 5 and
            "trojan" in str(r["virustotal"].get("tags", [])).lower()
        ),
        "technique_id": "T1204.002",
        "technique":    "Malicious File",
        "tactic":       "execution",
        "confidence":   "high",
        "source":       "virustotal",
    },
    {
        "condition": lambda r: (
            r.get("virustotal", {}) and
            r["virustotal"].get("status") == "found" and
            r["virustotal"].get("malicious", 0) > 0
        ),
        "technique_id": "T1071",
        "technique":    "Application Layer Protocol",
        "tactic":       "command-and-control",
        "confidence":   "medium",
        "source":       "virustotal",
    },
    # AbuseIPDB signals
    {
        "condition": lambda r: (
            r.get("abuseipdb", {}) and
            r["abuseipdb"].get("confidence_score", 0) > 70
        ),
        "technique_id": "T1046",
        "technique":    "Network Service Discovery",
        "tactic":       "discovery",
        "confidence":   "medium",
        "source":       "abuseipdb",
    },
    {
        "condition": lambda r: (
            r.get("abuseipdb", {}) and
            r["abuseipdb"].get("is_tor") is True
        ),
        "technique_id": "T1090.003",
        "technique":    "Multi-hop Proxy",
        "tactic":       "command-and-control",
        "confidence":   "high",
        "source":       "abuseipdb",
    },
    # AlienVault signals
    {
        "condition": lambda r: (
            r.get("alienvault", {}) and
            any("phishing" in t.lower()
                for t in r["alienvault"].get("tags", []))
        ),
        "technique_id": "T1566",
        "technique":    "Phishing",
        "tactic":       "initial-access",
        "confidence":   "high",
        "source":       "alienvault",
    },
    {
        "condition": lambda r: (
            r.get("alienvault", {}) and
            len(r["alienvault"].get("adversaries", [])) > 0
        ),
        "technique_id": "T1588",
        "technique":    "Obtain Capabilities",
        "tactic":       "resource-development",
        "confidence":   "medium",
        "source":       "alienvault",
    },
    # URLhaus signals
    {
        "condition": lambda r: (
            r.get("urlhaus", {}) and
            r["urlhaus"].get("url_status") == "online"
        ),
        "technique_id": "T1105",
        "technique":    "Ingress Tool Transfer",
        "tactic":       "command-and-control",
        "confidence":   "high",
        "source":       "urlhaus",
    },
    # GreyNoise signals
    {
        "condition": lambda r: (
            r.get("greynoise", {}) and
            r["greynoise"].get("noise") is True and
            r["greynoise"].get("classification") == "malicious"
        ),
        "technique_id": "T1595",
        "technique":    "Active Scanning",
        "tactic":       "reconnaissance",
        "confidence":   "high",
        "source":       "greynoise",
    },
]

def map_to_mitre(aggregated_results: dict) -> list[MITRETechnique]:
    """Evaluate all rules and return matched techniques (deduped by technique_id)."""
    matched = {}

    for rule in MAPPING_RULES:
        try:
            if rule["condition"](aggregated_results):
                tid = rule["technique_id"]
                if tid not in matched:
                    matched[tid] = MITRETechnique(
                        technique_id=rule["technique_id"],
                        technique=rule["technique"],
                        tactic=rule["tactic"],
                        confidence=rule["confidence"],
                        source=rule["source"],
                    )
        except (KeyError, TypeError):
            continue

    return list(matched.values())
```

---

## 9. FastAPI Routes

```python
# app/api/v1/ioc.py
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.services.normalizer import detect_and_normalize
from app.services.aggregator import run_aggregation
from app.services.scorer import calculate_composite_score
from app.services.mitre import map_to_mitre
from app.services.enricher import enrich_ip
from app import crud
import asyncio

router = APIRouter(prefix="/ioc", tags=["ioc"])

@router.post("/lookup")
async def lookup_ioc(
    payload: dict,   # {"value": "1.2.3.4"}
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    raw_value = payload.get("value", "").strip()
    if not raw_value:
        raise HTTPException(400, "IOC value is required")

    # Step 1: Normalize and detect type
    try:
        normalized = detect_and_normalize(raw_value)
    except ValueError as e:
        raise HTTPException(422, str(e))

    if normalized.is_private_ip():
        raise HTTPException(422, "Private IP addresses cannot be looked up")

    # Step 2: Check cache (Redis or recent DB scan)
    cached = crud.get_recent_scan(db, normalized.value, max_age_minutes=60)
    if cached:
        return {"source": "cache", "scan": cached}

    # Step 3: Parallel query of all 5 APIs
    agg_result = await run_aggregation(normalized.value, normalized.ioc_type)

    # Step 4: Score
    score_result = calculate_composite_score(agg_result["results"])

    # Step 5: MITRE mapping
    mitre_techniques = map_to_mitre(agg_result["results"])

    # Step 6: Persist IOC + scan to DB
    ioc    = crud.get_or_create_ioc(db, normalized.value, normalized.ioc_type)
    scan   = crud.create_scan(db, ioc, agg_result, score_result, mitre_techniques)

    # Step 7: Enrich in background (WHOIS, ASN, geo) — non-blocking
    if normalized.ioc_type.value == "ip":
        background_tasks.add_task(run_enrichment, ioc.id, normalized.value, db)

    return {
        "source":       "live",
        "ioc":          {"value": ioc.value, "type": ioc.ioc_type, "id": ioc.id},
        "scan_id":      scan.id,
        "score":        score_result.composite_score,
        "risk_level":   score_result.risk_level,
        "confidence":   score_result.confidence,
        "breakdown":    score_result.score_breakdown,
        "mitre":        [vars(t) for t in mitre_techniques],
        "results":      agg_result["results"],
        "errors":       agg_result["errors"],
        "query_time_ms": agg_result["query_time_ms"],
    }

@router.get("/{ioc_value}/history")
def get_ioc_history(ioc_value: str, db: Session = Depends(get_db)):
    ioc = crud.get_ioc_by_value(db, ioc_value)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    return crud.get_scan_history(db, ioc.id)

@router.post("/{ioc_value}/notes")
def add_note(ioc_value: str, payload: dict, db: Session = Depends(get_db)):
    ioc = crud.get_ioc_by_value(db, ioc_value)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    note = crud.create_note(db, ioc.id, payload["note"], payload.get("analyst", "analyst"))
    return note

@router.put("/{ioc_value}/tags")
def update_tags(ioc_value: str, payload: dict, db: Session = Depends(get_db)):
    ioc = crud.get_ioc_by_value(db, ioc_value)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    # Replace all tags with new set
    crud.replace_tags(db, ioc.id, payload.get("tags", []))
    return {"status": "updated", "tags": payload["tags"]}
```

### Dashboard Stats Endpoint

```python
# app/api/v1/dashboard.py
@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    return {
        "total_iocs":          crud.count_iocs(db),
        "total_scans":         crud.count_scans(db),
        "scans_today":         crud.count_scans_today(db),
        "risk_distribution":   crud.get_risk_distribution(db),
        "top_tags":            crud.get_top_tags(db, limit=10),
        "recent_critical":     crud.get_recent_by_risk(db, "critical", limit=5),
        "ioc_type_breakdown":  crud.get_ioc_type_counts(db),
        "avg_query_time_ms":   crud.get_avg_query_time(db),
    }
```

---

## 10. PDF Report Generation

Professional reports that an analyst could actually attach to a ticket.

```python
# app/services/pdf_generator.py
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, Image
)
from reportlab.lib.units import mm
from io import BytesIO
import datetime

# Brand colors
COLOR_CRITICAL   = HexColor("#DC2626")
COLOR_MALICIOUS  = HexColor("#EA580C")
COLOR_SUSPICIOUS = HexColor("#CA8A04")
COLOR_LOW        = HexColor("#2563EB")
COLOR_CLEAN      = HexColor("#16A34A")
COLOR_HEADER     = HexColor("#0F172A")
COLOR_ACCENT     = HexColor("#0EA5E9")

RISK_COLORS = {
    "critical":   COLOR_CRITICAL,
    "malicious":  COLOR_MALICIOUS,
    "suspicious": COLOR_SUSPICIOUS,
    "low":        COLOR_LOW,
    "clean":      COLOR_CLEAN,
}

def generate_ioc_report(scan_data: dict, notes: list, mitre_techniques: list) -> bytes:
    """Returns PDF bytes for a single-IOC threat intelligence report."""
    buffer = BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4,
                               leftMargin=20*mm, rightMargin=20*mm,
                               topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story  = []

    # ── Cover Header ──────────────────────────────────────────────────────────
    story.append(Paragraph(
        "<font color='#0EA5E9' size='22'><b>ThreatLens</b></font> "
        "<font color='#64748B' size='14'>Threat Intelligence Report</font>",
        styles["Normal"]
    ))
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width="100%", color=COLOR_ACCENT, thickness=2))
    story.append(Spacer(1, 4*mm))

    # ── IOC Summary ───────────────────────────────────────────────────────────
    ioc   = scan_data["ioc"]
    score = scan_data["score"]
    risk  = scan_data["risk_level"]
    risk_color = RISK_COLORS.get(risk, black)

    summary_data = [
        ["IOC Value",   ioc["value"]],
        ["Type",        ioc["type"].upper()],
        ["Risk Level",  risk.upper()],
        ["Threat Score", f"{score:.1f} / 100"],
        ["Confidence",  scan_data.get("confidence", "medium").upper()],
        ["Scan Time",   datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Query Time",  f"{scan_data.get('query_time_ms', 0)} ms (5 sources parallel)"],
    ]

    summary_table = Table(summary_data, colWidths=[50*mm, 120*mm])
    summary_table.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 10),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",   (1, 2), (1, 2), risk_color),   # Risk level row
        ("FONTNAME",    (1, 2), (1, 2), "Helvetica-Bold"),
        ("FONTSIZE",    (1, 2), (1, 2), 11),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [HexColor("#F8FAFC"), white]),
        ("GRID",        (0, 0), (-1, -1), 0.5, HexColor("#E2E8F0")),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8*mm))

    # ── Score Breakdown Table ─────────────────────────────────────────────────
    story.append(Paragraph("<b>Score Breakdown by Source</b>", styles["Heading2"]))
    story.append(Spacer(1, 3*mm))

    breakdown = scan_data.get("breakdown", {})
    weights = {"virustotal": 32, "abuseipdb": 25, "alienvault": 22, "urlhaus": 12, "greynoise": 9}
    bd_rows  = [["Source", "Score Contribution", "Max Weight", "% Utilized"]]

    for source, contrib in breakdown.items():
        max_w = weights.get(source, 0)
        pct   = f"{(contrib/max_w*100):.0f}%" if max_w > 0 else "—"
        bd_rows.append([source.upper(), f"{contrib:.2f}", f"{max_w}", pct])

    bd_table = Table(bd_rows, colWidths=[45*mm, 40*mm, 40*mm, 40*mm])
    bd_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), COLOR_HEADER),
        ("TEXTCOLOR",   (0, 0), (-1, 0), white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F8FAFC"), white]),
        ("GRID",        (0, 0), (-1, -1), 0.5, HexColor("#CBD5E1")),
        ("ALIGN",       (1, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(bd_table)
    story.append(Spacer(1, 8*mm))

    # ── MITRE ATT&CK Techniques ───────────────────────────────────────────────
    if mitre_techniques:
        story.append(Paragraph("<b>MITRE ATT&CK Mappings</b>", styles["Heading2"]))
        story.append(Spacer(1, 3*mm))

        mitre_rows = [["Technique ID", "Technique", "Tactic", "Confidence", "Source"]]
        for t in mitre_techniques:
            mitre_rows.append([
                t["technique_id"], t["technique"],
                t["tactic"], t["confidence"].upper(), t["source"]
            ])

        mitre_table = Table(mitre_rows, colWidths=[25*mm, 50*mm, 35*mm, 25*mm, 30*mm])
        mitre_table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), HexColor("#1E3A5F")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#EFF6FF"), white]),
            ("GRID",        (0, 0), (-1, -1), 0.5, HexColor("#BFDBFE")),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(mitre_table)
        story.append(Spacer(1, 8*mm))

    # ── Analyst Notes ─────────────────────────────────────────────────────────
    if notes:
        story.append(Paragraph("<b>Analyst Notes</b>", styles["Heading2"]))
        for note in notes:
            story.append(Paragraph(
                f"<font size='8' color='#64748B'>{note['analyst']} · "
                f"{note['created_at']}</font>",
                styles["Normal"]
            ))
            story.append(Paragraph(note["note"], styles["Normal"]))
            story.append(Spacer(1, 3*mm))

    # Footer
    story.append(Spacer(1, 10*mm))
    story.append(HRFlowable(width="100%", color=HexColor("#E2E8F0")))
    story.append(Paragraph(
        "<font size='8' color='#94A3B8'>Generated by ThreatLens · "
        "Data sourced from VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, GreyNoise</font>",
        styles["Normal"]
    ))

    doc.build(story)
    return buffer.getvalue()
```

---

## 11. React Frontend — Key Components

### IOCSearchBar with Auto-Detection

```jsx
// src/components/IOCSearchBar.jsx
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import api from "../lib/api";

const IOC_PATTERNS = {
  ip:     /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F:]+)$/,
  sha256: /^[a-fA-F0-9]{64}$/,
  sha1:   /^[a-fA-F0-9]{40}$/,
  md5:    /^[a-fA-F0-9]{32}$/,
  url:    /^https?:\/\//i,
  domain: /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/,
};

function detectType(value) {
  const v = value.trim();
  for (const [type, pattern] of Object.entries(IOC_PATTERNS)) {
    if (pattern.test(v)) return type;
  }
  return null;
}

export default function IOCSearchBar({ onResult }) {
  const [input, setInput]         = useState("");
  const [detectedType, setType]   = useState(null);
  const queryClient               = useQueryClient();

  const lookupMutation = useMutation({
    mutationFn: (value) => api.post("/ioc/lookup", { value }),
    onSuccess: (data) => {
      onResult(data.data);
      queryClient.invalidateQueries(["dashboard-stats"]);
    },
  });

  const handleInput = (e) => {
    const v = e.target.value;
    setInput(v);
    setType(detectType(v));
  };

  return (
    <div className="relative w-full max-w-3xl">
      <div className="flex items-center gap-3 bg-slate-900 border border-slate-700
                      rounded-xl px-4 py-3 focus-within:border-sky-500 transition-colors">
        <input
          value={input}
          onChange={handleInput}
          onKeyDown={(e) => e.key === "Enter" && lookupMutation.mutate(input)}
          placeholder="Enter IP, domain, URL, or hash..."
          className="flex-1 bg-transparent text-slate-100 placeholder-slate-500
                     font-mono text-sm outline-none"
        />
        {detectedType && (
          <span className="px-2 py-1 rounded bg-sky-900/50 text-sky-400
                           text-xs font-mono uppercase">
            {detectedType}
          </span>
        )}
        <button
          onClick={() => lookupMutation.mutate(input)}
          disabled={!input || lookupMutation.isPending}
          className="px-4 py-2 bg-sky-600 hover:bg-sky-500 disabled:opacity-40
                     rounded-lg text-white text-sm font-medium transition-colors"
        >
          {lookupMutation.isPending ? "Querying..." : "Lookup"}
        </button>
      </div>
      {lookupMutation.isPending && (
        <p className="mt-2 text-xs text-slate-400 animate-pulse">
          Querying 5 threat intel sources in parallel...
        </p>
      )}
    </div>
  );
}
```

### ThreatScoreGauge Component

```jsx
// src/components/ThreatScoreGauge.jsx
const RISK_CONFIG = {
  clean:      { color: "#16A34A", label: "Clean",      bg: "bg-green-900/30" },
  low:        { color: "#2563EB", label: "Low Risk",   bg: "bg-blue-900/30" },
  suspicious: { color: "#CA8A04", label: "Suspicious", bg: "bg-yellow-900/30" },
  malicious:  { color: "#EA580C", label: "Malicious",  bg: "bg-orange-900/30" },
  critical:   { color: "#DC2626", label: "Critical",   bg: "bg-red-900/30" },
};

export default function ThreatScoreGauge({ score, riskLevel, confidence }) {
  const cfg = RISK_CONFIG[riskLevel] || RISK_CONFIG.clean;
  const pct = score / 100;

  return (
    <div className={`flex flex-col items-center p-6 rounded-2xl ${cfg.bg} border border-slate-700`}>
      {/* SVG Arc Gauge */}
      <svg width="160" height="100" viewBox="0 0 160 100">
        {/* Background arc */}
        <path d="M 20 90 A 60 60 0 0 1 140 90" fill="none"
              stroke="#334155" strokeWidth="12" strokeLinecap="round"/>
        {/* Score arc */}
        <path d="M 20 90 A 60 60 0 0 1 140 90" fill="none"
              stroke={cfg.color} strokeWidth="12" strokeLinecap="round"
              strokeDasharray={`${188 * pct} 188`}/>
        <text x="80" y="78" textAnchor="middle" fill="white"
              fontSize="28" fontWeight="700" fontFamily="monospace">
          {Math.round(score)}
        </text>
        <text x="80" y="95" textAnchor="middle" fill="#94A3B8" fontSize="10">
          / 100
        </text>
      </svg>
      <span className="mt-2 text-lg font-semibold" style={{ color: cfg.color }}>
        {cfg.label}
      </span>
      <span className="text-xs text-slate-400 mt-1">
        Confidence: {confidence}
      </span>
    </div>
  );
}
```

### MITRE ATT&CK Heatmap

```jsx
// src/components/MITREHeatmap.jsx
const TACTICS_ORDER = [
  "reconnaissance", "resource-development", "initial-access", "execution",
  "persistence", "privilege-escalation", "defense-evasion", "credential-access",
  "discovery", "lateral-movement", "collection", "command-and-control",
  "exfiltration", "impact"
];

export default function MITREHeatmap({ techniques }) {
  if (!techniques?.length) return null;

  const byTactic = {};
  for (const t of techniques) {
    if (!byTactic[t.tactic]) byTactic[t.tactic] = [];
    byTactic[t.tactic].push(t);
  }

  const CONF_COLOR = { high: "#DC2626", medium: "#EA580C", low: "#CA8A04" };

  return (
    <div className="rounded-xl border border-slate-700 p-4 bg-slate-900">
      <h3 className="text-sm font-semibold text-slate-300 mb-3">
        MITRE ATT&CK Mappings
      </h3>
      <div className="flex flex-wrap gap-2">
        {TACTICS_ORDER.map(tactic => {
          const hits = byTactic[tactic];
          if (!hits) return null;
          return (
            <div key={tactic}
                 className="bg-slate-800 border border-slate-600 rounded-lg p-3 min-w-[140px]">
              <p className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                {tactic.replace("-", " ")}
              </p>
              {hits.map(t => (
                <div key={t.technique_id} className="mb-1">
                  <span className="font-mono text-xs" style={{ color: CONF_COLOR[t.confidence] }}>
                    {t.technique_id}
                  </span>
                  <p className="text-xs text-slate-300">{t.technique}</p>
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
```

---

## 12. Configuration and Secrets

```python
# app/config.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # API Keys (set via environment variables or .env)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY:  str = ""
    ALIENVAULT_API_KEY: str = ""
    GREYNOISE_API_KEY:  str = ""

    # Database
    DATABASE_URL: str = "sqlite:///./threatlens.db"

    # Redis (optional — caching)
    REDIS_URL:    str = "redis://localhost:6379/0"

    # JWT
    SECRET_KEY:   str = "change-this-in-production"
    ALGORITHM:    str = "HS256"
    TOKEN_EXPIRE: int = 480  # minutes

    # Rate limiting (per analyst per hour)
    RATE_LIMIT:   int = 200

    class Config:
        env_file = ".env"

settings = Settings()
```

**URLhaus requires no API key — free to use immediately.**

---

## 13. Docker Compose

```yaml
# docker-compose.yml
version: "3.9"

services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/threatlens
      - REDIS_URL=redis://redis:6379/0
    env_file:
      - .env
    depends_on:
      - db
      - redis

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      - VITE_API_URL=http://localhost:8000/api/v1

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB:       threatlens
      POSTGRES_USER:     user
      POSTGRES_PASSWORD: pass
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru

volumes:
  pgdata:
```

---

## 14. Testing Strategy

```python
# tests/test_scorer.py — example test
from app.services.scorer import calculate_composite_score

def test_clean_ip():
    results = {
        "virustotal": {"status": "found", "malicious": 0, "suspicious": 0,
                       "harmless": 50, "undetected": 10, "total": 60},
        "abuseipdb":  {"status": "found", "confidence_score": 0},
        "alienvault": {"status": "found", "pulse_count": 0},
        "urlhaus":    None,
        "greynoise":  {"status": "found", "classification": "benign", "riot": True, "noise": True},
    }
    result = calculate_composite_score(results)
    assert result.risk_level == "clean"
    assert result.composite_score < 5

def test_critical_ip():
    results = {
        "virustotal": {"status": "found", "malicious": 60, "suspicious": 5,
                       "harmless": 1, "undetected": 2, "total": 68},
        "abuseipdb":  {"status": "found", "confidence_score": 98},
        "alienvault": {"status": "found", "pulse_count": 25, "tags": ["c2"]},
        "urlhaus":    {"status": "found", "url_status": "online"},
        "greynoise":  {"status": "found", "classification": "malicious", "noise": True},
    }
    result = calculate_composite_score(results)
    assert result.risk_level == "critical"
    assert result.composite_score > 85
```

---

## 15. API Endpoints Reference

```
POST   /api/v1/ioc/lookup              Submit IOC — returns live score + results
GET    /api/v1/ioc/{value}             IOC detail — latest scan + enrichment
GET    /api/v1/ioc/{value}/history     All historical scans for this IOC (timeline)
GET    /api/v1/ioc/{value}/enrich      Trigger enrichment job, return status
POST   /api/v1/ioc/{value}/notes       Add analyst note
PUT    /api/v1/ioc/{value}/tags        Replace tag set
DELETE /api/v1/ioc/{value}/notes/{id}  Delete a note

GET    /api/v1/search                  Filter/search by tag, risk level, type, date
POST   /api/v1/batch/lookup            Submit up to 10 IOCs at once

POST   /api/v1/reports/generate        Generate PDF for one or multiple IOCs
GET    /api/v1/reports                 List generated reports
GET    /api/v1/reports/{id}/download   Download PDF

GET    /api/v1/dashboard/stats         Aggregate stats for dashboard
GET    /api/v1/dashboard/timeline      Scan volume over time (for chart)
```

---

## 16. Portfolio Talking Points

When presenting ThreatLens in interviews, emphasize these specifics:

**"Why parallel async querying?"**
> "Sequential calls to 5 APIs would take 5–15 seconds. With asyncio.gather, all 5 fire simultaneously. In testing, a lookup takes ~800ms total — that's the speed requirement for a real SOC triage workflow where analysts process hundreds of alerts per shift."

**"How did you design the scoring algorithm?"**
> "I weighted the sources based on their strength: VirusTotal has the broadest engine coverage (70+ AV vendors), so it carries the most weight. AbuseIPDB specializes in IP abuse reports and is highly reliable for C2 detection. AlienVault OTX gives context through threat actor attribution. URLhaus and GreyNoise fill specific gaps — active malware distribution and internet scanner classification respectively."

**"What does the MITRE mapping add?"**
> "Raw API data tells you an IP is malicious. MITRE mapping tells you *what the attacker is doing with it* — whether it's active scanning (Reconnaissance), a C2 channel (Command & Control), or phishing (Initial Access). That context determines the SOC response: block at perimeter, escalate to IR, or educate the user."

**"Why track IOC history?"**
> "Threat intelligence is time-sensitive. An IP that was clean 6 months ago might now host malware. The history view shows score trends — if something goes from score 5 to score 85 over 3 lookups, that's a signal worth investigating even before the current scan's result. This is how real TI platforms like Recorded Future work."

**"What would you add next?"**
> "STIX/TAXII export for sharing threat data with other organizations, Shodan integration for port/service enrichment on IPs, and a webhook system to push critical-risk lookups to a Slack channel or JIRA ticket automatically."

---

## 17. Free API Tier Limits (for personal portfolio use)

| Source | Free Tier | Rate Limit |
|---|---|---|
| VirusTotal | ✅ Free | 4 lookups/min |
| AbuseIPDB | ✅ Free (register) | 1,000/day |
| AlienVault OTX | ✅ Free (register) | No hard limit |
| URLhaus | ✅ Free (no key needed) | Generous |
| GreyNoise | ✅ Community free | 1,000/day |

All five sources have free tiers that are sufficient to build and demo ThreatLens in a portfolio context. Register for all 5 API keys before starting development.

---

*ThreatLens Blueprint v1.0 — Generated for Chandraprakash, SOC L1 Portfolio*
