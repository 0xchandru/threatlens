import asyncio
import time
import aiohttp
from app.models.ioc import IOCType
from app.integrations import virustotal, abuseipdb, alienvault, urlhaus, greynoise

TIMEOUT = aiohttp.ClientTimeout(total=10)


async def query_all_sources(
    value: str,
    ioc_type: IOCType,
    session: aiohttp.ClientSession
) -> dict:
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
    async with aiohttp.ClientSession(
        timeout=TIMEOUT,
        connector=aiohttp.TCPConnector(limit=10)
    ) as session:
        return await query_all_sources(value, ioc_type, session)
