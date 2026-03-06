# app/services/threat_intel_Integerations/hybridanalysis_service.py
import os
import re
import urllib.parse
from datetime import datetime
from typing import Optional

import httpx


class HybridAnalysisService:
    """
    Hybrid Analysis integration.

    Key fix: follow_redirects=True on the AsyncClient.
    The HA API's POST /search/hash returns HTTP 301 → httpx would raise
    by default. With follow_redirects the client follows through to the
    actual JSON response.
    """

    BASE_URL = "https://www.hybrid-analysis.com/api/v2"

    _VERDICT_MAP = {
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
    def _base_headers(self) -> dict:
        return {
            "api-key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "Falcon Sandbox",
        }

    def _make_client(self) -> httpx.AsyncClient:
        # follow_redirects=True is critical — HA /search/hash issues a 301
        return httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    async def scan_indicator(
        self,
        indicator: str,
        ioc_type: str = "hash",
        include_summary: bool = True,
    ) -> dict:
        if ioc_type != "hash":
            raise ValueError("Hybrid Analysis only supports hash lookups.")
        self._validate_hash(indicator)

        async with self._make_client() as client:
            search_data = await self._search_hash(client, indicator)
            if not search_data:
                return self._not_found(indicator)

            # Resolve to SHA256 for subsequent calls
            sha256 = indicator
            sha256s: list = search_data.get("sha256s") or []
            if sha256s:
                sha256 = sha256s[0]

            overview_data = await self._get_overview(client, sha256) or {}
            summary_data: dict = {}
            if include_summary:
                summary_data = await self._get_summary(client, sha256) or {}

        return self._parse_result(
            indicator, sha256, search_data, overview_data, summary_data
        )

    async def get_threat_feed(self, limit: int = 50) -> list:
        async with self._make_client() as client:
            data = await self._get(client, "/feed/detonation")
        if not isinstance(data, list):
            return []
        return [self._parse_feed_item(item) for item in data[:limit]]

    async def get_quick_scan_feed(self, limit: int = 50) -> list:
        async with self._make_client() as client:
            data = await self._get(client, "/feed/quick-scan")
        if not isinstance(data, list):
            return []
        return [self._parse_feed_item(item, quick_scan=True) for item in data[:limit]]

    # ─────────────────────────────────────────────────────────────────────────
    # HTTP helpers
    # ─────────────────────────────────────────────────────────────────────────

    async def _search_hash(
        self, client: httpx.AsyncClient, hash_value: str
    ) -> Optional[dict]:
        try:
            # Must be urlencoded form, NOT JSON
            payload = urllib.parse.urlencode({"hash": hash_value})
            resp = await client.post(
                f"{self.BASE_URL}/search/hash",
                headers={
                    **self._base_headers,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                content=payload,
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
        return await self._get(client, f"/overview/{sha256}/summary") or {}

    async def _get(self, client: httpx.AsyncClient, endpoint: str) -> Optional[dict]:
        try:
            resp = await client.get(
                f"{self.BASE_URL}{endpoint}",
                headers=self._base_headers,
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
            raise RuntimeError("Hybrid Analysis rate limit exceeded.")
        if resp.status_code in (401, 403):
            raise RuntimeError("Invalid Hybrid Analysis API key.")
        if resp.status_code == 400:
            body = resp.json() if resp.content else {}
            raise ValueError(body.get("message", f"Bad request: {context}"))
        if not resp.is_success:
            raise RuntimeError(
                f"Hybrid Analysis API error {resp.status_code}: {context}"
            )

    # ─────────────────────────────────────────────────────────────────────────
    # Parsers
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_result(
        self,
        original: str,
        sha256: str,
        search: dict,
        overview: dict,
        summary: dict,
    ) -> dict:
        reports: list = search.get("reports") or []
        found = bool(reports or overview.get("sha256"))

        # Threat score
        ts = overview.get("threat_score")
        if ts is None and reports:
            mal = sum(1 for r in reports if r.get("verdict") in ("malicious", 60))
            sus = sum(1 for r in reports if r.get("verdict") in ("suspicious", 50))
            ts = min(100, round(((mal * 2 + sus) / len(reports)) * 100))
        threat_score = ts or 0

        # Verdict
        raw_verdict = (
            overview.get("verdict")
            or (reports[0].get("verdict") if reports else None)
            or "unknown"
        )
        verdict_str, verdict_num = self._normalise_verdict(raw_verdict)
        threat_level = self._VERDICT_MAP.get(verdict_num, "unknown")

        return {
            "ioc": original,
            "ioc_type": "hash",
            "found": found,
            "sha256": sha256,
            "threat_level": threat_level,
            "threat_score": threat_score,
            "verdict": verdict_str,
            "vx_family": overview.get("vx_family"),
            "last_file_name": overview.get("last_file_name"),
            "size": overview.get("size"),
            "type": overview.get("type"),
            "type_short": overview.get("type_short", []),
            "architecture": overview.get("architecture"),
            "tags": overview.get("tags", []),
            "submitted_at": overview.get("submitted_at"),
            "reports": [
                {
                    "id": r.get("id"),
                    "environment_description": r.get("environment_description"),
                    "state": r.get("state"),
                    "verdict": r.get("verdict"),
                }
                for r in reports
            ],
            "mitre_attcks": summary.get("mitre_attcks", []),
            "signatures": summary.get("signatures", []),
            "total_network_connections": summary.get("total_network_connections") or 0,
            "total_processes": summary.get("total_processes") or 0,
            "total_signatures": summary.get("total_signatures") or 0,
            "behavioral_indicators": self._behavioral(summary),
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
            "vx_family": None,
            "tags": [],
            "reports": [],
            "mitre_attcks": [],
            "signatures": [],
            "behavioral_indicators": [],
            "ha_url": f"https://www.hybrid-analysis.com/search?query={indicator}",
            "timestamp": datetime.utcnow().isoformat(),
        }

    @staticmethod
    def _parse_feed_item(item: dict, quick_scan: bool = False) -> dict:
        vmap = {
            60: "malicious",
            50: "suspicious",
            40: "no_specific_threat",
            30: "no_verdict",
            20: "whitelisted",
        }
        vn = item.get("verdict", 0)
        return {
            "report_id": item.get("quick_scan_id" if quick_scan else "report_id"),
            "sha256": item.get("sha256"),
            "submit_name": item.get("submit_name"),
            "verdict": vn,
            "verdict_human": item.get("verdict_human") or vmap.get(vn, "unknown"),
            "environment_description": item.get("environment_description"),
        }

    def _normalise_verdict(self, raw) -> tuple:
        if isinstance(raw, int):
            return self._VERDICT_MAP.get(raw, "unknown"), raw
        label = str(raw).lower().replace(" ", "_")
        reverse = {v: k for k, v in self._VERDICT_MAP.items()}
        return label, reverse.get(label, 0)

    @staticmethod
    def _behavioral(summary: dict) -> list:
        out = []
        for a in (summary.get("mitre_attcks") or [])[:3]:
            out.append(f"MITRE: {a.get('technique', '')} ({a.get('tactic', '')})")
        for s in sorted(
            summary.get("signatures") or [],
            key=lambda x: x.get("threat_level", 0),
            reverse=True,
        )[:3]:
            if s.get("threat_level", 0) >= 3:
                out.append(f"Signature: {s.get('name', '')}")
        if summary.get("total_network_connections"):
            out.append(f"Network connections: {summary['total_network_connections']}")
        if summary.get("total_processes"):
            out.append(f"Processes created: {summary['total_processes']}")
        return out[:10]

    @staticmethod
    def _validate_hash(h: str) -> None:
        c = h.strip().lower()
        if not re.match(r"^[0-9a-f]+$", c) or len(c) not in (32, 40, 64, 128):
            raise ValueError(
                "Invalid hash — expected MD5 (32), SHA1 (40), SHA256 (64), or SHA512 (128) hex chars."
            )
