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
        return None

    if not settings.ABUSEIPDB_API_KEY:
        return {"status": "no_api_key", "source": "abuseipdb"}

    headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": value, "maxAgeInDays": 90, "verbose": True}

    async with session.get(ABUSEIPDB_URL, headers=headers, params=params) as resp:
        if resp.status == 401:
            return {"status": "invalid_api_key"}
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
    }
