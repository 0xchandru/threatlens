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
        return None

    if not settings.GREYNOISE_API_KEY:
        return {"status": "no_api_key", "source": "greynoise"}

    headers = {"key": settings.GREYNOISE_API_KEY}
    async with session.get(f"{GN_BASE}/{value}", headers=headers) as resp:
        if resp.status == 404:
            return {"status": "not_found", "classification": "unknown"}
        if resp.status == 401:
            return {"status": "invalid_api_key"}
        resp.raise_for_status()
        data = await resp.json()

    return {
        "status":         "found",
        "classification": data.get("classification"),
        "noise":          data.get("noise", False),
        "riot":           data.get("riot", False),
        "name":           data.get("name"),
        "link":           data.get("link"),
        "last_seen":      data.get("last_seen"),
        "message":        data.get("message"),
    }
