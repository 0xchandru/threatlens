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
    try:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 404:
                return {"status": "not_found", "pulse_count": 0}
            if resp.status == 401:
                return {"status": "invalid_api_key"}
            if resp.status != 200:
                return {"status": "error", "code": resp.status}
            data = await resp.json()
    except Exception as e:
        return {"status": "error", "error": str(e)}

    if not isinstance(data, dict):
        return {"status": "error", "error": "unexpected response format"}

    try:
        pulse_info = data.get("pulse_info", {})
        if not isinstance(pulse_info, dict):
            pulse_info = {}
        pulses = pulse_info.get("pulses", [])
        if not isinstance(pulses, list):
            pulses = []

        indicator = data.get("indicator", {})
        threat_score = None
        if isinstance(indicator, dict):
            threat_score = indicator.get("threat_score")

        tags = []
        malware_families = []
        adversaries = []
        pulse_names = []
        for p in pulses:
            if not isinstance(p, dict):
                continue
            p_tags = p.get("tags", [])
            if isinstance(p_tags, list):
                tags.extend(p_tags)
            p_mf = p.get("malware_families", [])
            if isinstance(p_mf, list):
                malware_families.extend(p_mf)
            p_adv = p.get("adversary", [])
            if isinstance(p_adv, list):
                adversaries.extend([a for a in p_adv if a])
            elif isinstance(p_adv, str) and p_adv:
                adversaries.append(p_adv)
            if p.get("name"):
                pulse_names.append(p.get("name"))

        return {
            "status":           "found",
            "pulse_count":      len(pulses),
            "threat_score":     threat_score,
            "tags":             list(set(tags)),
            "malware_families": list(set(malware_families)),
            "adversaries":      list(set(adversaries)),
            "pulse_names":      pulse_names[:5],
        }
    except Exception as e:
        return {"status": "error", "error": f"parse error: {str(e)}"}
