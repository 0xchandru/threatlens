import aiohttp
from app.config import settings
from app.models.ioc import IOCType

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"

SECTION_MAP = {
    IOCType.ip:     ("IPv4",   ["general"]),
    IOCType.domain: ("domain", ["general"]),
    IOCType.url:    ("url",    ["general"]),
    IOCType.md5:    ("file",   ["general"]),
    IOCType.sha1:   ("file",   ["general"]),
    IOCType.sha256: ("file",   ["general"]),
}


async def query(
    session: aiohttp.ClientSession,
    value: str,
    ioc_type: IOCType
) -> dict | None:
    if not settings.ALIENVAULT_API_KEY:
        return {"status": "no_api_key", "source": "alienvault"}

    if ioc_type not in SECTION_MAP:
        return None

    headers = {"X-OTX-API-KEY": settings.ALIENVAULT_API_KEY}
    indicator_type, _ = SECTION_MAP[ioc_type]

    url = f"{OTX_BASE}/{indicator_type}/{value}/general"
    async with session.get(url, headers=headers) as resp:
        if resp.status == 404:
            return {"status": "not_found", "pulse_count": 0}
        if resp.status == 401:
            return {"status": "invalid_api_key"}
        resp.raise_for_status()
        data = await resp.json()

    pulse_info = data.get("pulse_info", {})
    pulses = pulse_info.get("pulses", [])

    return {
        "status":           "found",
        "pulse_count":      len(pulses),
        "threat_score":     data.get("indicator", {}).get("threat_score"),
        "tags":             list({tag for p in pulses for tag in p.get("tags", [])}),
        "malware_families": list({mf for p in pulses for mf in p.get("malware_families", [])}),
        "adversaries":      list({a for p in pulses for a in p.get("adversary", []) if a}),
        "pulse_names":      [p.get("name") for p in pulses[:5]],
    }
