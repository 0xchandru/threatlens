import aiohttp
import base64
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
    if not settings.VIRUSTOTAL_API_KEY:
        return {"status": "no_api_key", "source": "virustotal"}

    if ioc_type not in ENDPOINT_MAP:
        return None

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    if ioc_type == IOCType.url:
        value_b64 = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        path = ENDPOINT_MAP[ioc_type].format(value_b64=value_b64)
    else:
        path = ENDPOINT_MAP[ioc_type].format(value=value)

    async with session.get(VT_BASE + path, headers=headers) as resp:
        if resp.status == 404:
            return {"status": "not_found"}
        if resp.status == 401:
            return {"status": "invalid_api_key"}
        resp.raise_for_status()
        data = await resp.json()

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    return {
        "status":             "found",
        "malicious":          stats.get("malicious", 0),
        "suspicious":         stats.get("suspicious", 0),
        "harmless":           stats.get("harmless", 0),
        "undetected":         stats.get("undetected", 0),
        "total":              sum(stats.values()),
        "tags":               attrs.get("tags", []),
        "reputation":         attrs.get("reputation", 0),
        "last_analysis_date": attrs.get("last_analysis_date"),
    }
