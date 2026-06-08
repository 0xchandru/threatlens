import asyncio
import aiohttp
import socket

IPAPI_URL = "https://ipapi.co/{ip}/json/"


async def enrich_ip(ip: str, session: aiohttp.ClientSession) -> dict:
    tasks = [
        _fetch_ipapi(ip, session),
        _fetch_rdns(ip),
    ]
    ipapi_result, rdns = await asyncio.gather(*tasks, return_exceptions=True)

    if isinstance(ipapi_result, Exception):
        ipapi_result = {}
    if isinstance(rdns, Exception):
        rdns = None

    return {
        "asn":           ipapi_result.get("asn"),
        "asn_org":       ipapi_result.get("org"),
        "country_code":  ipapi_result.get("country_code"),
        "country_name":  ipapi_result.get("country_name"),
        "city":          ipapi_result.get("city"),
        "rdns":          rdns,
        "is_datacenter": _is_datacenter(ipapi_result.get("org", "")),
    }


async def _fetch_ipapi(ip: str, session: aiohttp.ClientSession) -> dict:
    async with session.get(IPAPI_URL.format(ip=ip)) as resp:
        resp.raise_for_status()
        return await resp.json()


async def _fetch_rdns(ip: str) -> str | None:
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return result[0]
    except (socket.herror, OSError):
        return None


def _is_datacenter(org: str) -> bool:
    dc_keywords = ["amazon", "google", "microsoft", "digitalocean",
                   "linode", "vultr", "hetzner", "ovh", "cloudflare"]
    return any(kw in org.lower() for kw in dc_keywords)


async def run_enrichment(ioc_id: int, ip: str, db):
    from app import crud
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            data = await enrich_ip(ip, session)
        crud.upsert_enrichment(db, ioc_id, data)
    except Exception:
        pass
