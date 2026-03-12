# app/services/threat_intel_Integerations/hybridanalysis_service.py
import os
import re
from datetime import datetime
from typing import Optional

import httpx


class HybridAnalysisService:
    """
    Hybrid Analysis integration.

    Uses direct Hybrid Analysis v2 endpoints and normalises responses
    for frontend components.
    """

    BASE_URL = "https://hybrid-analysis.com/api/v2"

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
        # Keep redirects disabled for POST to avoid dropping body on 301.
        return httpx.AsyncClient(
            timeout=30,
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
            raw_search = await self._search_hash(client, indicator)
            search_data = self._normalise_search_data(raw_search)
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

    async def get_report_summary(self, report_id: str) -> Optional[dict]:
        """Fetch a detailed report summary by report/job ID."""
        async with self._make_client() as client:
            return await self._get(client, f"/report/{report_id}/summary")

    async def get_report_state(self, report_id: str) -> Optional[dict]:
        """Fetch report state by report/job ID."""
        async with self._make_client() as client:
            return await self._get(client, f"/report/{report_id}/state")

    async def get_report_details(self, report_id: str) -> Optional[dict]:
        """Fetch full report details by report/job ID."""
        async with self._make_client() as client:
            return await self._get(client, f"/report/{report_id}")

    # ─────────────────────────────────────────────────────────────────────────
    # HTTP helpers
    # ─────────────────────────────────────────────────────────────────────────

    async def _search_hash(
        self, client: httpx.AsyncClient, hash_value: str
    ) -> Optional[object]:
        try:
            resp = await client.post(
                f"{self.BASE_URL}/search/hash",
                headers={
                    **self._base_headers,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data={"hash": hash_value},
            )
            if resp.status_code == 404:
                return None
            self._raise_for_status(resp, "search/hash")
            return resp.json()
        except ValueError:
            raise
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
        reports: list = self._collect_reports(search, overview, summary)
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
        analysis_date = (
            overview.get("analysis_start_time")
            or overview.get("submitted_at")
            or datetime.utcnow().isoformat()
        )
        whitelisted = bool(overview.get("whitelisted") or verdict_num == 20)

        return {
            "ioc": original,
            "ioc_type": "hash",
            "found": found,
            "sha256": sha256,
            "threat_level": threat_level,
            "threat_score": threat_score,
            "threat_score_computed": threat_score,
            "verdict": verdict_str,
            "verdict_numeric": verdict_num,
            "vx_family": overview.get("vx_family"),
            "last_file_name": overview.get("last_file_name"),
            "size": overview.get("size"),
            "type": overview.get("type"),
            "type_short": overview.get("type_short", []),
            "architecture": overview.get("architecture"),
            "tags": overview.get("tags", []),
            "submitted_at": overview.get("submitted_at"),
            "analysis_date": analysis_date,
            "url_analysis": bool(overview.get("url_analysis", False)),
            "whitelisted": whitelisted,
            "reports": [
                {
                    "id": self._resolve_report_id(r),
                    "submission_id": r.get("submission_id"),
                    "environment_id": r.get("environment_id"),
                    "environment_description": r.get("environment_description"),
                    "state": r.get("state"),
                    "verdict": r.get("verdict"),
                }
                for r in reports
            ],
            "submissions": search.get("submissions") or [],
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
            "threat_score_computed": 0,
            "verdict": "unknown",
            "verdict_numeric": 0,
            "vx_family": None,
            "tags": [],
            "size": None,
            "type": None,
            "type_short": [],
            "last_file_name": None,
            "analysis_date": datetime.utcnow().isoformat(),
            "url_analysis": False,
            "whitelisted": False,
            "reports": [],
            "mitre_attcks": [],
            "signatures": [],
            "behavioral_indicators": [],
            "ha_url": f"https://www.hybrid-analysis.com/search?query={indicator}",
            "timestamp": datetime.utcnow().isoformat(),
        }

    @staticmethod
    def _normalise_search_data(data: Optional[object]) -> Optional[dict]:
        """
        Hybrid Analysis may return either:
        - dict with { reports: [...], sha256s: [...] }
        - list of report objects directly
        """
        if data is None:
            return None

        if isinstance(data, list):
            reports = [r for r in data if isinstance(r, dict)]
            sha256s = []
            for r in reports:
                s = r.get("sha256")
                if isinstance(s, str) and len(s) == 64:
                    sha256s.append(s)
            # keep order, remove duplicates
            seen = set()
            unique_sha256s = []
            for s in sha256s:
                if s not in seen:
                    seen.add(s)
                    unique_sha256s.append(s)
            return {
                "reports": reports,
                "sha256s": unique_sha256s,
            }

        if isinstance(data, dict):
            reports = data.get("reports")
            if not isinstance(reports, list):
                reports = []
            sha256s = data.get("sha256s")
            if not isinstance(sha256s, list):
                sha256s = []
            if not sha256s and reports:
                for r in reports:
                    if isinstance(r, dict):
                        s = r.get("sha256")
                        if isinstance(s, str) and len(s) == 64:
                            sha256s.append(s)
            return {
                **data,
                "reports": reports,
                "sha256s": sha256s,
            }

        return None

    @staticmethod
    def _collect_reports(search: dict, overview: dict, summary: dict) -> list:
        """Collect report-like records from all known HA payload locations."""
        merged = []

        def _add(items):
            if not isinstance(items, list):
                return
            for item in items:
                if isinstance(item, dict):
                    merged.append(item)

        _add(search.get("reports"))
        _add(overview.get("related_reports"))
        _add(overview.get("reports"))
        _add(summary.get("related_reports"))
        _add(summary.get("reports"))

        # Some HA responses for search/hash return one static-analysis object
        # with many submissions but no reports[]; provide fallback cards.
        if len(merged) <= 1:
            submissions = search.get("submissions")
            if isinstance(submissions, list) and len(submissions) > 1:
                env = search.get("environment_description") or "Static Analysis"
                state = search.get("state") or "SUCCESS"
                verdict = search.get("verdict") or "unknown"
                for sub in submissions:
                    sid = sub.get("submission_id") if isinstance(sub, dict) else None
                    merged.append(
                        {
                            "id": None,
                            "submission_id": sid,
                            "environment_id": search.get("environment_id"),
                            "environment_description": env,
                            "state": state,
                            "verdict": verdict,
                        }
                    )

        # De-duplicate while preserving order.
        out = []
        seen = set()
        for r in merged:
            key = (
                r.get("id"),
                r.get("submission_id"),
                r.get("environment_id"),
                r.get("environment_description"),
                r.get("state"),
                r.get("verdict"),
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
        return out

    @staticmethod
    def _resolve_report_id(report: dict) -> Optional[str]:
        """Resolve a usable report id from known HA fields."""
        for key in ("id", "report_id", "job_id", "analysis_id"):
            value = report.get(key)
            if isinstance(value, str) and value:
                return value
        return None

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
            "md5": item.get("md5"),
            "sha1": item.get("sha1"),
            "sha256": item.get("sha256"),
            "sha512": item.get("sha512"),
            "submit_name": item.get("submit_name"),
            "url_analysis": bool(item.get("url_analysis", False)),
            "size": item.get("size"),
            "mime": item.get("mime"),
            "type": item.get("type"),
            "type_short": item.get("type_short") or [],
            "environment_id": item.get("environment_id"),
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
