import asyncio
import re
from datetime import datetime
from urllib.parse import urlparse

from app.services.threat_intel_Integerations.abuseipdb_service import AbuseIPDBService
from app.services.threat_intel_Integerations.alienvault_service import (
    AlienVaultOTXService,
)
from app.services.threat_intel_Integerations.filescan_service import FileScanService
from app.services.threat_intel_Integerations.hybridanalysis_service import (
    HybridAnalysisService,
)
from app.services.threat_intel_Integerations.malwarebazaar_service import (
    MalwareBazaarService,
)
from app.services.threat_intel_Integerations.threatfox_service import ThreatFoxService
from app.services.threat_intel_Integerations.virustotal_service import VirusTotalService


class UnifiedThreatIntelService:
    """
    Orchestrates all threat intel services.
    Detects input type, fans out to relevant services in parallel,
    and returns a normalised summary.
    """

    # FileScan and HybridAnalysis are hash-only services.
    # FileScan also accepts URLs.
    SERVICE_MAP = {
        "ip": ["virustotal", "abuseipdb", "alienvault", "threatfox"],
        "domain": ["virustotal", "alienvault", "threatfox"],
        "url": ["virustotal", "threatfox", "filescan"],
        "hash": [
            "virustotal",
            "malwarebazaar",
            "alienvault",
            "threatfox",
            "filescan",
            "hybrid_analysis",
        ],
        "tag": ["malwarebazaar", "threatfox"],
        "unknown": ["virustotal", "malwarebazaar", "alienvault"],
    }

    def __init__(self):
        self.vt = VirusTotalService()
        self.mb = MalwareBazaarService()
        self.otx = AlienVaultOTXService()
        self.abuseipdb = AbuseIPDBService()
        self.threatfox = ThreatFoxService()
        self.filescan = FileScanService()
        self.hybrid_analysis = HybridAnalysisService()

    # -------------------------------------------------------------------------
    # Input type detection
    # -------------------------------------------------------------------------

    def detect_input_type(self, indicator: str) -> str:
        s = indicator.strip()

        ipv4 = re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
        )
        if ipv4.match(s):
            return "ip"

        ipv6 = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
        if ipv6.match(s):
            return "ip"

        try:
            parsed = urlparse(s)
            if parsed.scheme in ("http", "https", "ftp") and parsed.netloc:
                return "url"
        except Exception:
            pass

        domain = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,}$"
        )
        if domain.match(s):
            return "domain"

        hash_lengths = {32, 40, 64, 128}
        if re.match(r"^[a-fA-F0-9]+$", s) and len(s) in hash_lengths:
            return "hash"

        return "tag"

    # -------------------------------------------------------------------------
    # Public entry point
    # -------------------------------------------------------------------------

    async def unified_search(self, indicator: str) -> dict:
        input_type = self.detect_input_type(indicator)
        services = self.SERVICE_MAP.get(input_type, self.SERVICE_MAP["unknown"])

        tasks: dict = {}
        if "virustotal" in services:
            tasks["virustotal"] = self._search_vt(indicator, input_type)
        if "malwarebazaar" in services:
            tasks["malwarebazaar"] = self._search_mb(indicator, input_type)
        if "alienvault" in services:
            tasks["alienvault"] = self._search_otx(indicator, input_type)
        if "abuseipdb" in services and input_type == "ip":
            tasks["abuseipdb"] = self._search_abuseipdb(indicator)
        if "threatfox" in services:
            tasks["threatfox"] = self._search_threatfox(indicator)
        if "filescan" in services:
            tasks["filescan"] = self._search_filescan(indicator, input_type)
        if "hybrid_analysis" in services:
            tasks["hybrid_analysis"] = self._search_hybrid_analysis(indicator)

        results_list = await asyncio.gather(*tasks.values(), return_exceptions=True)
        results: dict = {}
        for key, result in zip(tasks.keys(), results_list):
            if isinstance(result, Exception):
                results[key] = {
                    "source": key,
                    "success": False,
                    "data": None,
                    "error": str(result),
                    "timestamp": datetime.utcnow().isoformat(),
                }
            else:
                results[key] = result

        summary = self._calculate_summary(results)

        return {
            "input": indicator,
            "input_type": input_type,
            "results": results,
            "summary": summary,
            "timestamp": datetime.utcnow().isoformat(),
        }

    # -------------------------------------------------------------------------
    # Per-service wrappers
    # -------------------------------------------------------------------------

    async def _search_vt(self, indicator: str, input_type: str) -> dict:
        try:
            vt_type = "hash" if input_type in ("hash", "tag") else input_type
            if vt_type not in ("hash", "ip", "domain", "url"):
                vt_type = "hash"
            data = await self.vt.scan_indicator(
                indicator=indicator,
                ioc_type=vt_type,
                include_relationships=(input_type == "hash"),
            )
            return {
                "source": "virustotal",
                "success": True,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "source": "virustotal",
                "success": False,
                "data": None,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def _search_mb(self, indicator: str, input_type: str) -> dict:
        try:
            search_type = "hash" if input_type == "hash" else "tag"
            data = await self.mb.search_indicator(indicator, search_type)
            return {
                "source": "malwarebazaar",
                "success": True,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "source": "malwarebazaar",
                "success": False,
                "data": None,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def _search_otx(self, indicator: str, input_type: str) -> dict:
        try:
            otx_type = (
                input_type if input_type in ("ip", "domain", "url", "hash") else "hash"
            )
            data = await self.otx.scan_indicator(indicator, otx_type)
            return {
                "source": "alienvault",
                "success": True,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "source": "alienvault",
                "success": False,
                "data": None,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def _search_abuseipdb(self, ip: str) -> dict:
        try:
            data = await self.abuseipdb.check_ip(ip)
            return {
                "source": "abuseipdb",
                "success": True,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "source": "abuseipdb",
                "success": False,
                "data": None,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def _search_threatfox(self, indicator: str) -> dict:
        try:
            data = await self.threatfox.search_indicator(indicator)
            is_error = data.get("query_status") == "error" or bool(data.get("error"))
            return {
                "source": "threatfox",
                "success": not is_error,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "source": "threatfox",
                "success": False,
                "data": None,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def _search_filescan(self, indicator: str, input_type: str) -> dict:
        """
        FileScan supports URL scanning directly and hash lookups via similarity search.
        For hashes in a unified search we do a similarity search as a lightweight probe.
        Full file scanning (upload) is initiated separately from the dedicated endpoints.
        """
        try:
            if input_type == "url":
                # Submit URL and immediately return the flow_id;
                # the caller can poll /filescan/status/{flow_id} for results.
                upload_result = await self.filescan.scan_url(
                    indicator, {"url_analysis": True}
                )
                data = {
                    "flow_id": upload_result.get("flow_id"),
                    "found": True,
                    "status": "submitted",
                    "note": "URL submitted for analysis. Poll /filescan/status/{flow_id} for results.",
                    "threat_level": "unknown",
                    "threat_score": 0,
                }
            elif input_type == "hash":
                # Use similarity search as a lightweight existence check
                sim = await self.filescan.similarity_search(indicator)
                most_similar = sim.get("most_similar", [])
                found = bool(most_similar)
                # Check if the exact hash appears in results
                exact_match = next(
                    (r for r in most_similar if r.get("sha256") == indicator), None
                )
                data = {
                    "found": found,
                    "exact_match": exact_match,
                    "similar_files": most_similar[:5],
                    "threat_level": "unknown",
                    "threat_score": 0,
                }
                if exact_match:
                    verdict = exact_match.get("details", {}).get("verdict", "UNKNOWN")
                    data["threat_level"] = FileScanService._VERDICT_MAP.get(
                        verdict.upper(), "unknown"
                    )
            else:
                return {
                    "source": "filescan",
                    "success": False,
                    "data": None,
                    "error": f"FileScan does not support indicator type: {input_type}",
                    "timestamp": datetime.utcnow().isoformat(),
                }

            return {
                "source": "filescan",
                "success": True,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "source": "filescan",
                "success": False,
                "data": None,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def _search_hybrid_analysis(self, indicator: str) -> dict:
        try:
            data = await self.hybrid_analysis.scan_indicator(
                indicator=indicator,
                ioc_type="hash",
                include_summary=False,  # keep the unified search fast
            )
            return {
                "source": "hybrid_analysis",
                "success": True,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "source": "hybrid_analysis",
                "success": False,
                "data": None,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    # -------------------------------------------------------------------------
    # Summary calculation
    # -------------------------------------------------------------------------

    def _calculate_summary(self, results: dict) -> dict:
        malicious = suspicious = clean = unknown = 0

        for key, result in results.items():
            if not result.get("success") or not result.get("data"):
                unknown += 1
                continue
            data = result["data"]
            tl = data.get("threat_level", "unknown")

            if tl in ("high", "malicious"):
                malicious += 1
            elif tl in ("medium", "low", "suspicious", "no_specific_threat"):
                suspicious += 1
            elif tl in ("clean", "benign", "no_threat", "whitelisted"):
                clean += 1
            else:
                # Fallback checks per service
                if (
                    key == "virustotal"
                    and data.get("detection_stats", {}).get("malicious", 0) > 0
                ):
                    malicious += 1
                elif key == "malwarebazaar" and data.get("found"):
                    malicious += 1
                elif key == "threatfox" and data.get("found"):
                    malicious += 1
                elif key == "abuseipdb" and data.get("confidence_score", 0) > 20:
                    suspicious += 1
                elif key == "hybrid_analysis" and data.get("found"):
                    # Use verdict_numeric if available
                    vn = data.get("verdict_numeric", 0)
                    if vn == 60:
                        malicious += 1
                    elif vn == 50:
                        suspicious += 1
                    else:
                        unknown += 1
                elif key == "filescan" and data.get("found"):
                    # Exact match with a known verdict
                    exact = data.get("exact_match")
                    if exact:
                        v = exact.get("details", {}).get("verdict", "UNKNOWN").upper()
                        if v in ("MALICIOUS", "LIKELY_MALICIOUS"):
                            malicious += 1
                        elif v == "SUSPICIOUS":
                            suspicious += 1
                        else:
                            unknown += 1
                    else:
                        unknown += 1
                else:
                    unknown += 1

        total = len(results)
        successful = sum(1 for r in results.values() if r.get("success"))

        return {
            "total_services": total,
            "successful": successful,
            "failed": total - successful,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "clean_count": clean,
            "unknown_count": unknown,
        }
