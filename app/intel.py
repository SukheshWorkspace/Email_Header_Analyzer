# =============================================================================
# intel.py — External threat intelligence lookups (AbuseIPDB)
# =============================================================================

import httpx

from app.config import ABUSE_CACHE, ABUSE_DB_KEY, logger

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Sentinel for cache misses that returned a real result of 0
_EMPTY_RESULT: dict = {"score": 0, "isp": "Unknown"}


async def async_check_abuse_db(ip: str) -> dict:
    """
    Queries AbuseIPDB for the given IP address.
    - Uses httpx.AsyncClient (truly async, no thread-pool waste).
    - Results are cached per-IP for 10 minutes to conserve API quota.
    - Gracefully returns a zero-score stub on any failure.
    """
    if not ip or not ABUSE_DB_KEY:
        return _EMPTY_RESULT.copy()

    if ip in ABUSE_CACHE:
        return ABUSE_CACHE[ip]

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                _ABUSEIPDB_URL,
                headers={
                    "Key": ABUSE_DB_KEY,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": "90",
                },
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            result = {
                "score": int(data.get("abuseConfidenceScore", 0)),
                "isp": str(data.get("isp", "Unknown")),
                "country": str(data.get("countryCode", "Unknown")),
                "total_reports": int(data.get("totalReports", 0)),
            }
            ABUSE_CACHE[ip] = result
            return result

    except httpx.HTTPStatusError as exc:
        logger.warning(
            "AbuseIPDB HTTP error",
            extra={"status_code": exc.response.status_code, "ip": ip},
        )
    except httpx.TimeoutException:
        logger.warning("AbuseIPDB request timed out", extra={"ip": ip})
    except Exception:
        logger.warning("AbuseIPDB lookup failed", exc_info=True)

    return _EMPTY_RESULT.copy()
