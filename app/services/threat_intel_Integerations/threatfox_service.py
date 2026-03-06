# app/services/threat_intel_Integerations/threatfox_service.py
import os
from datetime import datetime

import httpx


class ThreatFoxService:
    """
    Server-side ThreatFox / URLhaus integration.
    Uses the same API key for both ThreatFox and URLhaus (abuse.ch ecosystem).
    """

    BASE_URL = "https://threatfox-api.abuse.ch/api/v1"

    def __init__(self):
        self.api_key = os.getenv("THREATFOX_API_KEY", "")
        if not self.api_key:
            print("WARNING: THREATFOX_API_KEY not set — using anonymous access")

    @property
    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers

    async def search_indicator(self, indicator: str) -> dict:
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                resp = await client.post(
                    self.BASE_URL,
                    headers=self._headers,
                    json={"query": "search_ioc", "search_term": indicator},
                )
                if resp.status_code == 429:
                    raise RuntimeError("ThreatFox rate limit exceeded.")
                if not resp.is_success:
                    raise RuntimeError(f"ThreatFox API error {resp.status_code}")
                return self._parse_search(resp.json(), indicator)
            except RuntimeError:
                raise
            except httpx.TimeoutException:
                raise RuntimeError("ThreatFox request timed out.")
            except Exception as e:
                raise RuntimeError(f"ThreatFox request failed: {e}")

    async def get_recent_iocs(self, days: int = 3, limit: int = 20) -> list:
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                resp = await client.post(
                    self.BASE_URL,
                    headers=self._headers,
                    json={"query": "get_iocs", "days": days},
                )
                if not resp.is_success:
                    return []
                body = resp.json()
                data = body.get("data") or []
                return data[:limit]
            except Exception as e:
                print(f"[ThreatFox] get_recent_iocs error: {e}")
                return []

    async def get_malware_list(self) -> dict:
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                resp = await client.post(
                    self.BASE_URL,
                    headers=self._headers,
                    json={"query": "get_malware_list"},
                )
                if not resp.is_success:
                    return {}
                return resp.json().get("data", {})
            except Exception as e:
                print(f"[ThreatFox] get_malware_list error: {e}")
                return {}

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _parse_search(self, raw: dict, indicator: str) -> dict:
        query_status = raw.get("query_status", "")
        iocs = raw.get("data") or []
        found = bool(iocs) and query_status != "no_result"

        threat_level = "unknown"
        if found:
            # Use the highest confidence score to determine threat level
            max_confidence = max(
                (i.get("confidence_level", 0) for i in iocs), default=0
            )
            if max_confidence >= 75:
                threat_level = "high"
            elif max_confidence >= 50:
                threat_level = "medium"
            else:
                threat_level = "low"

        return {
            "ioc": indicator,
            "found": found,
            "threat_level": threat_level,
            "query_status": query_status,
            "iocs": [self._parse_ioc(i) for i in iocs[:10]],
            "total": len(iocs),
            "timestamp": datetime.utcnow().isoformat(),
        }

    @staticmethod
    def _parse_ioc(i: dict) -> dict:
        return {
            "id": i.get("id"),
            "ioc": i.get("ioc"),
            "ioc_type": i.get("ioc_type"),
            "ioc_type_desc": i.get("ioc_type_desc"),
            "malware": i.get("malware"),
            "malware_alias": i.get("malware_alias"),
            "malware_printable": i.get("malware_printable"),
            "confidence_level": i.get("confidence_level"),
            "threat_type": i.get("threat_type"),
            "threat_type_desc": i.get("threat_type_desc"),
            "first_seen": i.get("first_seen"),
            "last_seen": i.get("last_seen"),
            "reporter": i.get("reporter"),
            "reference": i.get("reference"),
            "tags": i.get("tags", []),
        }
