import os
from datetime import datetime
from typing import Any, Optional

import httpx


class HybridAnalysisService:
    """
    Server-side Hybrid Analysis integration.
    Supports hash lookup, overview + summary fetching,
    and threat-feed retrieval. API key never leaves the server.
    """

    BASE_URL = "https://www.hybrid-analysis.com/api/v2"

    # Numeric verdict codes used by the HA API
    _VERDICT_NUMERIC_MAP = {
        60: "malicious",
        50: "suspicious",
        40: "no_specific_threat",
        30: "no_verdict",
        20: "whitelisted",
    }

    def __init__(self):
        self.api_key = os.getenv("HYBRID_ANALYSIS_API_KEY", "")
        if not self.api_key:
            print("WARNING: HYBRID_ANALYSIS_API_KEY not set")

    @property
    def _headers(self) -> dict:
        return {
            "api-key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "Falcon Sandbox",
        }

    # -------------------------------------------------------------------------
    # Public entry point
    # -------------------------------------------------------------------------

    async def scan_indicator(
        self,
        indicator: str,
        ioc_type: str = "hash",
        include_summary: bool = True,
    ) -> dict:
        """
        Look up a hash (MD5 / SHA1 / SHA256 / SHA512) in Hybrid Analysis.
        Returns a normalised result dict ready for the frontend / unified service.
        """
        if ioc_type != "hash":
            raise ValueError(
                "Hybrid Analysis only supports hash lookups "
                "(MD5, SHA1, SHA256, SHA512)."
            )

        self._validate_hash(indicator)

        async with httpx.AsyncClient(timeout=30) as client:
            # Step 1 – search by hash to get SHA256 + sandbox reports
            search_data = await self._search_hash(client, indicator)

            if not search_data:
                return self._not_found(indicator)

            # Resolve to SHA256 if the caller passed an MD5 / SHA1
            sha256: str = indicator
            sha256s: list = search_data.get("sha256s") or []
            if sha256s:
                sha256 = sha256s[0]

            # Step 2 – overview (threat score, verdict, metadata)
            overview_data = await self._get_overview(client, sha256)

            # Step 3 – summary (MITRE, signatures, processes, etc.)
            summary_data: dict = {}
            if include_summary and overview_data:
                summary_data = await self._get_summary(client, sha256)

        return self._parse_result(
            original_hash=indicator,
            sha256=sha256,
            search_data=search_data,
            overview_data=overview_data or {},
            summary_data=summary_data,
        )

    # -------------------------------------------------------------------------
    # Threat feed
    # -------------------------------------------------------------------------

    async def get_threat_feed(self, limit: int = 50) -> list:
        """
        Fetch recent detonation results from the HA threat feed.
        Returns a list of normalised threat feed items.
        """
        async with httpx.AsyncClient(timeout=30) as client:
            data = await self._get(client, "/feed/detonation")
        if not isinstance(data, list):
            return []
        return [self._parse_feed_item(item) for item in data[:limit]]

    async def get_quick_scan_feed(self, limit: int = 50) -> list:
        """Fetch the quick-scan feed (no sandbox execution required)."""
        async with httpx.AsyncClient(timeout=30) as client:
            data = await self._get(client, "/feed/quick-scan")
        if not isinstance(data, list):
            return []
        return [self._parse_feed_item(item, quick_scan=True) for item in data[:limit]]

    # -------------------------------------------------------------------------
    # HTTP helpers
    # -------------------------------------------------------------------------

    async def _search_hash(
        self, client: httpx.AsyncClient, hash_value: str
    ) -> Optional[dict]:
        """POST /search/hash — returns { sha256s, reports, … } or None."""
        try:
            resp = await client.post(
                f"{self.BASE_URL}/search/hash",
                headers={
                    **self._headers,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data={"hash": hash_value},
            )
            if resp.status_code == 404:
                return None
            self._raise_for_status(resp, "search/hash")
            return resp.json()
        except RuntimeError:
            raise
        except Exception as exc:
            print(f"[HybridAnalysis] search/hash error: {exc}")
            return None

    async def _get_overview(
        self, client: httpx.AsyncClient, sha256: str
    ) -> Optional[dict]:
        return await self._get(client, f"/overview/{sha256}")

    async def _get_summary(self, client: httpx.AsyncClient, sha256: str) -> dict:
        result = await self._get(client, f"/overview/{sha256}/summary")
        return result or {}

    async def _get(self, client: httpx.AsyncClient, endpoint: str) -> Optional[dict]:
        try:
            resp = await client.get(
                f"{self.BASE_URL}{endpoint}",
                headers=self._headers,
            )
            if resp.status_code == 404:
                return None
            self._raise_for_status(resp, endpoint)
            return resp.json()
        except RuntimeError:
            raise
        except httpx.TimeoutException:
            print(f"[HybridAnalysis] timeout: {endpoint}")
            return None
        except Exception as exc:
            print(f"[HybridAnalysis] error {endpoint}: {exc}")
            return None

    @staticmethod
    def _raise_for_status(resp: httpx.Response, context: str) -> None:
        if resp.status_code == 429:
            raise RuntimeError(
                "Hybrid Analysis rate limit exceeded. Please try again later."
            )
        if resp.status_code in (401, 403):
            raise RuntimeError(
                "Invalid Hybrid Analysis API key or insufficient permissions."
            )
        if resp.status_code == 400:
            body = resp.json() if resp.content else {}
            raise ValueError(
                body.get("message", f"Hybrid Analysis bad request: {context}")
            )
        if not resp.is_success:
            raise RuntimeError(
                f"Hybrid Analysis API error {resp.status_code}: {context}"
            )

    # -------------------------------------------------------------------------
    # Parsers
    # -------------------------------------------------------------------------

    def _parse_result(
        self,
        original_hash: str,
        sha256: str,
        search_data: dict,
        overview_data: dict,
        summary_data: dict,
    ) -> dict:
        reports: list = search_data.get("reports") or []
        found = bool(reports or overview_data.get("sha256"))

        # ── Threat score ──────────────────────────────────────────────────────
        threat_score_raw: Optional[int] = overview_data.get("threat_score")
        if threat_score_raw is None and reports:
            mal = sum(1 for r in reports if r.get("verdict") in ("malicious", 60))
            sus = sum(1 for r in reports if r.get("verdict") in ("suspicious", 50))
            threat_score_raw = min(
                100,
                round(((mal * 2 + sus) / len(reports)) * 100),
            )
        threat_score_computed = threat_score_raw or 0

        # ── Verdict ───────────────────────────────────────────────────────────
        raw_verdict = (
            overview_data.get("verdict")
            or (reports[0].get("verdict") if reports else None)
            or "unknown"
        )
        verdict_str, verdict_numeric = self._normalise_verdict(raw_verdict)

        # ── Threat level ──────────────────────────────────────────────────────
        threat_level = self._verdict_to_threat_level(verdict_numeric)

        # ── Behavioral indicators ─────────────────────────────────────────────
        behavioral = self._extract_behavioral_indicators(summary_data)

        return {
            "ioc": original_hash,
            "ioc_type": "hash",
            "found": found,
            "sha256": sha256,
            "threat_level": threat_level,
            "threat_score": threat_score_computed,
            "verdict": verdict_str,
            "verdict_numeric": verdict_numeric,
            # File metadata
            "last_file_name": overview_data.get("last_file_name"),
            "other_file_names": overview_data.get("other_file_name", []),
            "size": overview_data.get("size"),
            "type": overview_data.get("type"),
            "type_short": overview_data.get("type_short", []),
            "architecture": overview_data.get("architecture"),
            "vx_family": overview_data.get("vx_family"),
            "tags": overview_data.get("tags", []),
            # Scan metadata
            "submitted_at": overview_data.get("submitted_at"),
            "analysis_start_time": overview_data.get("analysis_start_time"),
            "last_multi_scan": overview_data.get("last_multi_scan"),
            "multiscan_result": overview_data.get("multiscan_result"),
            "url_analysis": overview_data.get("url_analysis", False),
            "whitelisted": overview_data.get("whitelisted", False),
            # Sandbox reports
            "reports": [
                {
                    "id": r.get("id"),
                    "environment_id": r.get("environment_id"),
                    "environment_description": r.get("environment_description"),
                    "state": r.get("state"),
                    "error_type": r.get("error_type"),
                    "error_origin": r.get("error_origin"),
                    "verdict": r.get("verdict"),
                }
                for r in reports
            ],
            # Scanners (AV results)
            "scanners": overview_data.get("scanners"),
            # Related hashes
            "related_parent_hashes": overview_data.get("related_parent_hashes", []),
            "related_children_hashes": overview_data.get("related_children_hashes", []),
            # Behavioral summary
            "mitre_attcks": summary_data.get("mitre_attcks", []),
            "signatures": summary_data.get("signatures", []),
            "processes": summary_data.get("processes", []),
            "extracted_files": summary_data.get("extracted_files", []),
            "classification_tags": summary_data.get("classification_tags", []),
            "total_network_connections": (
                summary_data.get("total_network_connections") or 0
            ),
            "total_processes": (summary_data.get("total_processes") or 0),
            "total_signatures": (summary_data.get("total_signatures") or 0),
            # Community
            "community_score_votes_up": overview_data.get("community_score_votes_up"),
            "community_score_votes_down": overview_data.get(
                "community_score_votes_down"
            ),
            # Behavioral indicators (pre-computed for the unified summary)
            "behavioral_indicators": behavioral,
            # URLs
            "ha_url": f"https://www.hybrid-analysis.com/sample/{sha256}",
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _not_found(self, indicator: str) -> dict:
        return {
            "ioc": indicator,
            "ioc_type": "hash",
            "found": False,
            "sha256": indicator,
            "threat_level": "unknown",
            "threat_score": 0,
            "verdict": "unknown",
            "verdict_numeric": 0,
            "tags": [],
            "reports": [],
            "behavioral_indicators": [],
            "ha_url": f"https://www.hybrid-analysis.com/search?query={indicator}",
            "timestamp": datetime.utcnow().isoformat(),
        }

    @staticmethod
    def _parse_feed_item(item: dict, quick_scan: bool = False) -> dict:
        verdict_num = item.get("verdict", 0)
        verdict_map = {
            60: "malicious",
            50: "suspicious",
            40: "no_specific_threat",
            30: "no_verdict",
            20: "whitelisted",
        }
        return {
            "report_id": item.get("quick_scan_id")
            if quick_scan
            else item.get("report_id"),
            "md5": item.get("md5"),
            "sha1": item.get("sha1"),
            "sha256": item.get("sha256"),
            "sha512": item.get("sha512"),
            "submit_name": item.get("submit_name"),
            "url_analysis": item.get("url_analysis", False),
            "size": item.get("size"),
            "mime": item.get("mime"),
            "type": item.get("type"),
            "type_short": item.get("type_short", []),
            "environment_id": item.get("environment_id"),
            "environment_description": item.get("environment_description"),
            "verdict": verdict_num,
            "verdict_human": (
                item.get("verdict_human") or verdict_map.get(verdict_num, "unknown")
            ),
        }

    # -------------------------------------------------------------------------
    # Scoring helpers
    # -------------------------------------------------------------------------

    def _normalise_verdict(self, raw: Any) -> tuple[str, int]:
        """Return (verdict_string, verdict_numeric)."""
        if isinstance(raw, int):
            label = self._VERDICT_NUMERIC_MAP.get(raw, "unknown")
            return label, raw
        label = str(raw).lower()
        reverse = {v: k for k, v in self._VERDICT_NUMERIC_MAP.items()}
        numeric = reverse.get(label, 0)
        return label, numeric

    @staticmethod
    def _verdict_to_threat_level(verdict_numeric: int) -> str:
        mapping = {
            60: "malicious",
            50: "suspicious",
            40: "no_specific_threat",
            30: "no_verdict",
            20: "whitelisted",
        }
        return mapping.get(verdict_numeric, "unknown")

    @staticmethod
    def _extract_behavioral_indicators(summary: dict) -> list[str]:
        indicators: list[str] = []
        for attack in (summary.get("mitre_attcks") or [])[:3]:
            indicators.append(
                f"MITRE: {attack.get('technique', '')} ({attack.get('tactic', '')})"
            )
        for sig in sorted(
            (summary.get("signatures") or []),
            key=lambda s: s.get("threat_level", 0),
            reverse=True,
        )[:3]:
            if sig.get("threat_level", 0) >= 3:
                indicators.append(f"Signature: {sig.get('name', '')}")
        if summary.get("total_network_connections"):
            indicators.append(
                f"Network connections: {summary['total_network_connections']}"
            )
        if summary.get("total_processes"):
            indicators.append(f"Processes created: {summary['total_processes']}")
        if summary.get("extracted_files"):
            indicators.append(f"Files extracted: {len(summary['extracted_files'])}")
        return indicators[:10]

    # -------------------------------------------------------------------------
    # Input validation
    # -------------------------------------------------------------------------

    @staticmethod
    def _validate_hash(hash_value: str) -> None:
        import re

        clean = hash_value.strip().lower()
        if not re.match(r"^[0-9a-f]+$", clean) or len(clean) not in (32, 40, 64, 128):
            raise ValueError(
                "Invalid hash. Must be MD5 (32), SHA1 (40), SHA256 (64), "
                "or SHA512 (128) hex characters."
            )
