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
        "status":     "found",
        "url_status": data.get("url_status"),
        "threat":     data.get("threat"),
        "tags":       data.get("tags") or [],
        "date_added": data.get("date_added"),
        "reporter":   data.get("reporter"),
        "payloads":   data.get("payloads", [])[:3],
    }
