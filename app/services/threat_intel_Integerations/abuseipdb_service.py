import os
from datetime import datetime

import httpx
from app.utils.logger import get_logger

_logger = get_logger("app.services.abuseipdb")


class AbuseIPDBService:
    """Server-side AbuseIPDB integration."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self):
        self.api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        if not self.api_key:
            _logger.warning("ABUSEIPDB_API_KEY not set")

    @property
    def _headers(self) -> dict:
        return {
            "Key": self.api_key,
            "Accept": "application/json",
        }

    async def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """Check an IP address against AbuseIPDB."""
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/check",
                    headers=self._headers,
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": max_age_days,
                        "verbose": "",
                    },
                )
                if response.status_code == 401:
                    raise RuntimeError("Invalid AbuseIPDB API key.")
                if response.status_code == 429:
                    raise RuntimeError("AbuseIPDB rate limit exceeded.")
                if response.status_code == 422:
                    return self._not_found(ip, "Invalid IP address format.")
                if not response.is_success:
                    return self._not_found(ip, f"API error: {response.status_code}")

                data = response.json().get("data", {})
                return self._parse(data, ip)

            except RuntimeError:
                raise
            except httpx.TimeoutException:
                raise RuntimeError("AbuseIPDB request timed out.")  # noqa: B904
            except Exception as e:
                _logger.exception("[AbuseIPDB] Error checking %s: %s", ip, e)
                return self._not_found(ip, str(e))

    async def check_block(self, network: str, limit: int = 10) -> dict:
        """Check a CIDR block for abusive IPs."""
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/check-block",
                    headers=self._headers,
                    params={"network": network, "maxAgeInDays": 30},
                )
                if not response.is_success:
                    return {"network": network, "found": False, "results": []}
                data = response.json()
                return {
                    "network": network,
                    "found": True,
                    "results": (data.get("data", {}).get("reportedAddress") or [])[
                        :limit
                    ],
                    "timestamp": datetime.utcnow().isoformat(),
                }
            except Exception as e:
                _logger.exception("[AbuseIPDB] Block check error: %s", e)
                return {"network": network, "found": False, "results": []}

    # -------------------------------------------------------------------------
    # Parsers
    # -------------------------------------------------------------------------

    def _parse(self, data: dict, ip: str) -> dict:
        confidence = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)

        if confidence >= 75 or total_reports > 50:
            threat_level = "high"
        elif confidence >= 40 or total_reports > 10:
            threat_level = "medium"
        elif confidence >= 10 or total_reports > 0:
            threat_level = "low"
        else:
            threat_level = "clean"

        return {
            "ioc": ip,
            "ioc_type": "ip",
            "found": total_reports > 0,
            "confidence_score": confidence,
            "total_reports": total_reports,
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "threat_level": threat_level,
            "is_public": data.get("isPublic", True),
            "is_tor": data.get("isTor", False),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "reports": (data.get("reports") or [])[:10],
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _not_found(self, ip: str, reason: str = "Not found") -> dict:
        return {
            "ioc": ip,
            "ioc_type": "ip",
            "found": False,
            "confidence_score": 0,
            "total_reports": 0,
            "threat_level": "unknown",
            "error": reason,
            "timestamp": datetime.utcnow().isoformat(),
        }
