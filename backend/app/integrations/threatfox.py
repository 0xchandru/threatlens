import aiohttp
from app.models.ioc import IOCType
from app.config import settings

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


async def query(
    session: aiohttp.ClientSession,
    value: str,
    ioc_type: IOCType
) -> dict | None:
    if ioc_type not in (
        IOCType.ip, IOCType.domain, IOCType.url,
        IOCType.md5, IOCType.sha256, IOCType.sha1
    ):
        return None

    headers = {}
    if settings.THREATFOX_API_KEY:
        headers["Auth-Key"] = settings.THREATFOX_API_KEY

    payload = {"query": "search_ioc", "search_term": value}

    try:
        async with session.post(THREATFOX_URL, json=payload, headers=headers) as resp:
            if resp.status == 401:
                return {"status": "invalid_api_key"}
            if resp.status != 200:
                return {"status": "error", "code": resp.status}
            data = await resp.json()
    except Exception as e:
        return {"status": "error", "error": str(e)}

    if not isinstance(data, dict):
        return {"status": "error", "error": "unexpected response format"}

    if data.get("query_status") == "no_result" or not data.get("data"):
        return {"status": "not_found"}

    entries = data["data"]
    max_confidence = max((e.get("confidence_level", 0) for e in entries), default=0)
    threat_types   = list({e.get("threat_type", "") for e in entries if e.get("threat_type")})
    malware_list   = list({e.get("malware_printable", "") for e in entries if e.get("malware_printable")})
    tags           = list({t for e in entries for t in (e.get("tags") or [])})

    return {
        "status":          "found",
        "ioc_count":       len(entries),
        "confidence_level": max_confidence,
        "threat_types":    threat_types,
        "malware":         malware_list,
        "tags":            tags,
        "first_seen":      entries[0].get("first_seen"),
        "last_seen":       entries[-1].get("last_seen"),
    }
