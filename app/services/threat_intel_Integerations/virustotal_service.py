import os
import re
from datetime import datetime
from typing import Any, List, Optional

import httpx
from app.utils.logger import get_logger

_logger = get_logger("app.services.virustotal")


class VirusTotalService:
    """Server-side VirusTotal integration — API key never leaves the server."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if not self.api_key:
            _logger.warning("VIRUSTOTAL_API_KEY not set")

    @property
    def _headers(self) -> dict:
        return {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    # -------------------------------------------------------------------------
    # Public entry point
    # -------------------------------------------------------------------------

    async def scan_indicator(
        self,
        indicator: str,
        ioc_type: str,
        include_relationships: bool = False,
    ) -> dict:
        """
        Scan a hash, IP, domain, or URL against VirusTotal.
        Returns a normalised result dict ready for the frontend.
        """
        async with httpx.AsyncClient(timeout=30) as client:
            match ioc_type:
                case "hash":
                    return await self._scan_hash(
                        client, indicator, include_relationships
                    )
                case "ip":
                    return await self._scan_ip(client, indicator, include_relationships)
                case "domain":
                    return await self._scan_domain(
                        client, indicator, include_relationships
                    )
                case "url":
                    return await self._scan_url(client, indicator)
                case _:
                    raise ValueError(f"Unsupported indicator type: {ioc_type}")

    # -------------------------------------------------------------------------
    # Indicator scanners
    # -------------------------------------------------------------------------

    async def _scan_hash(
        self, client: httpx.AsyncClient, hash_: str, include_relationships: bool
    ) -> dict:
        data = await self._get(client, f"/files/{hash_}")
        if not data or data.get("error"):
            return self._not_found(hash_, "hash")

        result = self._parse_file(data, hash_)

        if include_relationships:
            contacted_ips, contacted_domains, behaviors = await self._gather(
                self._get(client, f"/files/{hash_}/contacted_ips", {"limit": 10}),
                self._get(client, f"/files/{hash_}/contacted_domains", {"limit": 10}),
                self._get(client, f"/files/{hash_}/behaviours", {"limit": 2}),
            )
            result["relationships"] = {
                "contacted_ips": self._extract_ids(contacted_ips),
                "contacted_domains": self._extract_ids(contacted_domains),
            }
            if behaviors and not behaviors.get("error"):
                result["behavioral_indicators"] = self._extract_behavioral_indicators(
                    behaviors
                )
                result["sandbox_data"] = behaviors

        return result

    async def _scan_ip(
        self, client: httpx.AsyncClient, ip: str, include_relationships: bool
    ) -> dict:
        data = await self._get(client, f"/ip_addresses/{ip}")
        if not data or data.get("error"):
            return self._not_found(ip, "ip")

        result = self._parse_ip(data, ip)

        if include_relationships:
            resolutions, files = await self._gather(
                self._get(client, f"/ip_addresses/{ip}/resolutions", {"limit": 10}),
                self._get(
                    client, f"/ip_addresses/{ip}/communicating_files", {"limit": 10}
                ),
            )
            result["relationships"] = {
                "resolved_domains": self._extract_hostnames(resolutions),
                "communicating_files": self._extract_ids(files),
            }

        return result

    async def _scan_domain(
        self, client: httpx.AsyncClient, domain: str, include_relationships: bool
    ) -> dict:
        data = await self._get(client, f"/domains/{domain}")
        if not data or data.get("error"):
            return self._not_found(domain, "domain")

        result = self._parse_domain(data, domain)

        if include_relationships:
            resolutions, subdomains = await self._gather(
                self._get(client, f"/domains/{domain}/resolutions", {"limit": 10}),
                self._get(client, f"/domains/{domain}/subdomains", {"limit": 10}),
            )
            result["relationships"] = {
                "resolved_ips": self._extract_ips(resolutions),
                "subdomains": self._extract_ids(subdomains),
            }

        return result

    async def _scan_url(self, client: httpx.AsyncClient, url: str) -> dict:
        import base64

        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data = await self._get(client, f"/urls/{url_id}")
        if not data or data.get("error"):
            return self._not_found(url, "url")
        return self._parse_url(data, url)

    # -------------------------------------------------------------------------
    # HTTP helper
    # -------------------------------------------------------------------------

    async def _get(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        params: Optional[dict] = None,
    ) -> Optional[dict]:
        """Single GET with error handling. Returns None on non-fatal errors."""
        try:
            response = await client.get(
                f"{self.BASE_URL}{endpoint}",
                headers=self._headers,
                params=params or {},
            )
            if response.status_code == 404:
                return None
            if response.status_code == 429:
                raise RuntimeError(
                    "VirusTotal rate limit exceeded. Please try again later."
                )
            if response.status_code == 401:
                raise RuntimeError("Invalid VirusTotal API key.")
            if not response.is_success:
                return None
            return response.json()
        except httpx.TimeoutException:
            _logger.warning("VT timeout: %s", endpoint)
            return None
        except RuntimeError:
            raise
        except Exception as e:
            _logger.exception("VT request error %s: %s", endpoint, e)
            return None

    async def _gather(self, *coroutines):
        """Run multiple coroutines concurrently, returning None for failures."""
        import asyncio

        results: List[Any] = await asyncio.gather(*coroutines, return_exceptions=True)
        return [None if isinstance(r, Exception) else r for r in results]

    # -------------------------------------------------------------------------
    # Parsers
    # -------------------------------------------------------------------------

    def _parse_file(self, data: dict, hash_: str) -> dict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        detection_stats = self._build_detection_stats(stats)
        threat_classification = self._extract_threat_classification(attrs)
        return {
            "ioc": hash_,
            "ioc_type": "hash",
            "found": True,
            "detection_stats": detection_stats,
            "threat_level": self._threat_level(detection_stats),
            "threat_score": detection_stats["threat_score"],
            "threat_classification": threat_classification,
            "file_info": {
                "hash": hash_,
                "filename": attrs.get("meaningful_name")
                or (attrs.get("names") or [None])[0],
                "size": attrs.get("size"),
                "type_description": attrs.get("type_description"),
                "first_seen": self._ts(attrs.get("first_submission_date")),
                "last_analysis": self._ts(attrs.get("last_analysis_date")),
                "reputation": attrs.get("reputation", 0),
                "tags": attrs.get("tags", []),
            },
            "behavioral_indicators": [],
            "relationships": {},
            "raw_data": data,
            "vt_url": f"https://www.virustotal.com/gui/file/{hash_}",
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _extract_threat_classification(self, attrs: dict) -> dict:
        classification = attrs.get("popular_threat_classification") or {}
        label = (
            classification.get("popular_threat_label")
            or classification.get("suggested_threat_label")
            or ""
        )
        categories_raw = classification.get("popular_threat_category") or []
        name_raw = classification.get("popular_threat_name") or ""

        def normalize_ranked_values(raw: Any) -> list[str]:
            values: list[str] = []
            if isinstance(raw, str):
                text = raw.strip().lower()
                if text:
                    values.append(text)
            elif isinstance(raw, dict):
                value = raw.get("value") or raw.get("name") or raw.get("label")
                if value:
                    text = str(value).strip().lower()
                    if text:
                        values.append(text)
            elif isinstance(raw, list):
                for item in raw:
                    values.extend(normalize_ranked_values(item))
            elif raw:
                text = str(raw).strip().lower()
                if text:
                    values.append(text)

            deduped: list[str] = []
            for value in values:
                if value not in deduped:
                    deduped.append(value)
            return deduped

        categories = normalize_ranked_values(categories_raw)
        names = normalize_ranked_values(name_raw)
        name = " ".join(names)
        family_labels: list[str] = []

        def add_tokens(value: str) -> None:
            if not isinstance(value, str):
                value = str(value)
            for token in re.split(r"[\s,;:/._-]+", value):
                cleaned = token.strip().lower()
                if cleaned and cleaned not in family_labels:
                    family_labels.append(cleaned)

        # Keep the raw label plus tokenized family names for downstream ML/UI.
        if label:
            add_tokens(label)
        if name:
            add_tokens(name)
        if not categories and label:
            base = label.split(".", 1)[0]
            if base and base not in family_labels:
                family_labels.insert(0, base.lower())

        generic_tokens = {"malware", "trojan", "ransomware", "worm", "adware", "spyware", "backdoor", "loader", "dropper", "unknown"}
        specific_family = None
        if label:
            tail = label.split(".", 1)[-1]
            if "/" in tail:
                pieces = [piece.strip().lower() for piece in tail.split("/") if piece.strip()]
                if pieces:
                    specific_family = pieces[-1]
            elif tail:
                specific_family = tail.strip().lower()

        if (not specific_family or specific_family in generic_tokens) and family_labels:
            for token in reversed(family_labels):
                if token and token not in generic_tokens:
                    specific_family = token
                    break

        return {
            "popular_threat_label": label or None,
            "popular_threat_name": names[0] if names else None,
            "popular_threat_category": categories,
            "family_labels": family_labels,
            "specific_family": specific_family,
        }

    def _parse_ip(self, data: dict, ip: str) -> dict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        detection_stats = self._build_detection_stats(stats)
        return {
            "ioc": ip,
            "ioc_type": "ip",
            "found": True,
            "detection_stats": detection_stats,
            "threat_level": self._threat_level(detection_stats),
            "threat_score": detection_stats["threat_score"],
            "network_info": {
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "country": attrs.get("country"),
                "network": attrs.get("network"),
                "categories": list(attrs.get("categories", {}).values()),
            },
            "behavioral_indicators": [],
            "relationships": {},
            "raw_data": data,
            "vt_url": f"https://www.virustotal.com/gui/ip-address/{ip}",
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _parse_domain(self, data: dict, domain: str) -> dict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        detection_stats = self._build_detection_stats(stats)
        return {
            "ioc": domain,
            "ioc_type": "domain",
            "found": True,
            "detection_stats": detection_stats,
            "threat_level": self._threat_level(detection_stats),
            "threat_score": detection_stats["threat_score"],
            "network_info": {
                "registrar": attrs.get("registrar"),
                "categories": list(attrs.get("categories", {}).values()),
            },
            "behavioral_indicators": [],
            "relationships": {},
            "raw_data": data,
            "vt_url": f"https://www.virustotal.com/gui/domain/{domain}",
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _parse_url(self, data: dict, url: str) -> dict:
        import base64

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        detection_stats = self._build_detection_stats(stats)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return {
            "ioc": url,
            "ioc_type": "url",
            "found": True,
            "detection_stats": detection_stats,
            "threat_level": self._threat_level(detection_stats),
            "threat_score": detection_stats["threat_score"],
            "behavioral_indicators": [],
            "relationships": {},
            "raw_data": data,
            "vt_url": f"https://www.virustotal.com/gui/url/{url_id}",
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _not_found(self, indicator: str, ioc_type: str) -> dict:
        empty_stats = {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "timeout": 0,
            "total": 0,
            "detection_ratio": "0/0",
            "threat_score": 0,
        }
        return {
            "ioc": indicator,
            "ioc_type": ioc_type,
            "found": False,
            "detection_stats": empty_stats,
            "threat_level": "unknown",
            "threat_score": 0,
            "behavioral_indicators": [],
            "relationships": {},
            "raw_data": {"data": {"attributes": {"error": "Indicator not found in VirusTotal"}}},
            "vt_url": f"https://www.virustotal.com/gui/{ioc_type}/{indicator}",
            "timestamp": datetime.utcnow().isoformat(),
        }

    # -------------------------------------------------------------------------
    # Scoring helpers
    # -------------------------------------------------------------------------

    def _build_detection_stats(self, stats: dict) -> dict:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        timeout = stats.get("timeout", 0)
        total = malicious + suspicious + harmless + undetected + timeout

        threat_score = 0
        if total > 0:
            raw = (malicious * 10 + suspicious * 5) / total * 10
            threat_score = min(round(raw * 10), 100)

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "total": total,
            "detection_ratio": f"{malicious + suspicious}/{total}",
            "threat_score": threat_score,
        }

    def _threat_level(self, stats: dict) -> str:
        if stats["total"] == 0:
            return "unknown"
        score = stats["threat_score"]
        ratio = stats["malicious"] / stats["total"]
        if score >= 70 or ratio >= 0.2:
            return "high"
        if score >= 40 or ratio >= 0.05:
            return "medium"
        if score >= 10 or stats["suspicious"] > 0:
            return "low"
        if stats["malicious"] == 0 and stats["suspicious"] == 0:
            return "clean"
        return "unknown"

    # -------------------------------------------------------------------------
    # Extraction helpers
    # -------------------------------------------------------------------------

    def _extract_ids(self, data: Optional[dict]) -> list:
        if not data or not data.get("data"):
            return []
        return [item["id"] for item in data["data"] if item.get("id")]

    def _extract_hostnames(self, data: Optional[dict]) -> list:
        if not data or not data.get("data"):
            return []
        return [
            item.get("attributes", {}).get("host_name")
            for item in data["data"]
            if item.get("attributes", {}).get("host_name")
        ]

    def _extract_ips(self, data: Optional[dict]) -> list:
        if not data or not data.get("data"):
            return []
        return [
            item.get("attributes", {}).get("ip_address")
            for item in data["data"]
            if item.get("attributes", {}).get("ip_address")
        ]

    def _extract_behavioral_indicators(self, behavior_data: dict) -> list:
        indicators = []
        for behavior in (behavior_data.get("data") or [])[:2]:
            summary = behavior.get("attributes", {}).get("summary", {})
            checks = [
                ("files_written", "Files written"),
                ("files_dropped", "Files dropped"),
                ("registry_keys_set", "Registry modifications"),
                ("processes_created", "Processes created"),
                ("dns_lookups", "DNS lookups"),
            ]
            for key, label in checks:
                if summary.get(key):
                    indicators.append(f"{label}: {len(summary[key])}")
            for technique in (summary.get("mitre_attack_techniques") or [])[:3]:
                indicators.append(f"MITRE: {technique}")
        return indicators[:10]

    def _ts(self, timestamp: Optional[int]) -> Optional[str]:
        if not timestamp:
            return None
        return datetime.utcfromtimestamp(timestamp).isoformat()
