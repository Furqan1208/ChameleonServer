import os
from datetime import datetime
from typing import Any, Optional

import httpx


class FileScanService:
    """
    Server-side FileScan.io integration.
    Supports file upload, URL scanning, status polling, report fetching,
    and similarity search. API key never leaves the server.
    """

    BASE_URL = "https://www.filescan.io/api"

    # Verdict string → normalised threat_level
    _VERDICT_MAP = {
        "MALICIOUS": "high",
        "LIKELY_MALICIOUS": "high",
        "SUSPICIOUS": "medium",
        "INFORMATIONAL": "low",
        "NO_THREAT": "clean",
        "BENIGN": "clean",
        "UNKNOWN": "unknown",
    }

    # Numeric threat level (0-5) → label
    _THREAT_LEVEL_LABELS = {
        0: "none",
        1: "low",
        2: "medium",
        3: "high",
        4: "critical",
        5: "severe",
    }

    def __init__(self):
        self.api_key = os.getenv("FILESCAN_API_KEY", "")
        if not self.api_key:
            print("WARNING: FILESCAN_API_KEY not set")

    @property
    def _headers(self) -> dict:
        return {
            "X-Api-Key": self.api_key,
            "Accept": "application/json",
        }

    # -------------------------------------------------------------------------
    # Public — file / URL scanning
    # -------------------------------------------------------------------------

    async def upload_file(
        self,
        file_content: bytes,
        filename: str,
        options: Optional[dict] = None,
    ) -> dict:
        """
        Upload a file for scanning. Returns { flow_id, priority }.
        `options` may contain any FileScanOptions fields as strings/bools.
        """
        async with httpx.AsyncClient(timeout=60) as client:
            files = {"file": (filename, file_content, "application/octet-stream")}
            data = self._build_form_data(options or {})
            resp = await client.post(
                f"{self.BASE_URL}/scan/file",
                headers=self._headers,
                files=files,
                data=data,
            )
            return self._handle_upload_response(resp, "file upload")

    async def scan_url(
        self,
        url: str,
        options: Optional[dict] = None,
    ) -> dict:
        """
        Submit a URL for scanning. Returns { flow_id, priority }.
        """
        async with httpx.AsyncClient(timeout=30) as client:
            data = {"url": url, **self._build_form_data(options or {})}
            resp = await client.post(
                f"{self.BASE_URL}/scan/url",
                headers=self._headers,
                data=data,
            )
            return self._handle_upload_response(resp, "URL scan")

    # -------------------------------------------------------------------------
    # Public — status & reports
    # -------------------------------------------------------------------------

    async def get_scan_status(
        self,
        flow_id: str,
        filters: Optional[list[str]] = None,
    ) -> dict:
        """
        Poll scan progress. When state == 'finished' all reports are ready.
        `filters` is a list of report sections to include
        (e.g. ['general', 'finalVerdict', 'allSignalGroups']).
        """
        params: dict[str, Any] = {}
        if filters:
            params["filter"] = ",".join(filters)

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.BASE_URL}/scan/{flow_id}/report",
                headers=self._headers,
                params=params,
            )
            return self._handle_response(resp, f"status for flow {flow_id}")

    async def get_report(
        self,
        report_id: str,
        file_hash: str,
        filters: Optional[list[str]] = None,
    ) -> dict:
        """
        Fetch a specific report by report_id + file_hash.
        Returns the full FileScanStatusResponse structure.
        """
        params: dict[str, Any] = {}
        if filters:
            params["filter"] = ",".join(filters)

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.BASE_URL}/reports/{report_id}/{file_hash}",
                headers=self._headers,
                params=params,
            )
            return self._handle_response(resp, f"report {report_id}/{file_hash}")

    # -------------------------------------------------------------------------
    # Public — similarity search
    # -------------------------------------------------------------------------

    async def similarity_search(
        self,
        file_hash: str,
        min_similarity: float = 0.0,
        verdict: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> dict:
        """
        Find files similar to the given hash.
        Returns { most_similar: [...], most_recent: [...] }.
        """
        params: dict[str, Any] = {
            "hash": file_hash,
            "minSimilarity": str(min_similarity),
        }
        if verdict:
            params["verdict"] = verdict
        if tags:
            params["tags"] = ",".join(tags)

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.BASE_URL}/files/search/similarity",
                headers=self._headers,
                params=params,
            )
            return self._handle_response(resp, f"similarity search for {file_hash}")

    # -------------------------------------------------------------------------
    # Public — full analysis (status + report + similarity combined)
    # -------------------------------------------------------------------------

    async def get_full_analysis(self, flow_id: str) -> dict:
        """
        Retrieve a normalised AnalysisResult from a completed scan.
        Raises RuntimeError if the scan is not yet finished.
        """
        status = await self.get_scan_status(
            flow_id,
            filters=["general", "finalVerdict"],
        )

        state = status.get("state", "")
        if state != "finished":
            raise RuntimeError(f"Scan {flow_id} is not finished yet (state: {state})")

        reports: dict = status.get("reports", {})
        if not reports:
            raise RuntimeError(f"No reports found for flow {flow_id}")

        report_id = next(iter(reports))
        status_report = reports[report_id]

        file_hash = self._extract_hash(status_report)
        if not file_hash:
            raise RuntimeError("Could not determine file hash from scan report")

        # Fetch richer report data (safe filters only)
        full_report = status_report
        try:
            detailed = await self.get_report(
                report_id,
                file_hash,
                filters=["general", "finalVerdict", "allSignalGroups", "allTags"],
            )
            full_report = detailed.get("reports", {}).get(report_id, status_report)
        except Exception as exc:
            print(f"[FileScan] Could not fetch detailed report: {exc}")

        # Similarity search (best-effort)
        similar_files: list = []
        try:
            sim = await self.similarity_search(file_hash)
            similar_files = sim.get("most_similar", [])
        except Exception:
            pass

        return self._build_analysis_result(
            flow_id=flow_id,
            report_id=report_id,
            status=status,
            report=full_report,
            similar_files=similar_files,
        )

    # -------------------------------------------------------------------------
    # Builders
    # -------------------------------------------------------------------------

    def _build_analysis_result(
        self,
        flow_id: str,
        report_id: str,
        status: dict,
        report: dict,
        similar_files: list,
    ) -> dict:
        file_hash = self._extract_hash(report)
        final_verdict: dict = report.get("finalVerdict") or {}
        verdict_str: str = final_verdict.get("verdict", "UNKNOWN")

        file_info = report.get("file") or {}
        if not file_info.get("hash") and file_hash:
            file_info = {**file_info, "hash": file_hash}

        return {
            "flow_id": flow_id,
            "scan_id": report_id,
            "file": {
                "name": file_info.get("name", "unknown"),
                "hash": file_info.get("hash", file_hash),
                "type": file_info.get("type", "unknown"),
                "size": file_info.get("size"),
            },
            "state": status.get("state", "finished"),
            "verdict": {
                "verdict": verdict_str,
                "threat_level": final_verdict.get("threatLevel", 0),
                "confidence": final_verdict.get("confidence", 0),
                "verdict_label": final_verdict.get("verdictLabel", verdict_str),
            },
            "threat_level": self._VERDICT_MAP.get(verdict_str, "unknown"),
            "threat_score": self._compute_threat_score(
                verdict_str,
                final_verdict.get("threatLevel", 0),
                final_verdict.get("confidence", 0),
            ),
            "interesting_score": report.get("interestingScore"),
            "vt_rate": report.get("vtRate"),
            "created_date": report.get("created_date", datetime.utcnow().isoformat()),
            "scan_options": report.get("scanOptions", {}),
            "chatgpt_summary": report.get("chatGptSummary"),
            "similar_files": similar_files,
            "signal_groups": report.get("allSignalGroups", []),
            "tags": report.get("allTags", report.get("tags", [])),
            "report_url": f"https://www.filescan.io/reports/{report_id}/{file_hash}",
            "scan_url": f"https://www.filescan.io/scan/{flow_id}",
            "timestamp": datetime.utcnow().isoformat(),
        }

    # -------------------------------------------------------------------------
    # HTTP helpers
    # -------------------------------------------------------------------------

    def _handle_upload_response(self, resp: httpx.Response, context: str) -> dict:
        if resp.status_code == 429:
            raise RuntimeError("FileScan rate limit exceeded. Please try again later.")
        if resp.status_code == 401:
            raise RuntimeError("Invalid FileScan API key.")
        if resp.status_code == 400:
            body = resp.json() if resp.content else {}
            raise ValueError(
                body.get("message", f"FileScan bad request during {context}")
            )
        if not resp.is_success:
            raise RuntimeError(
                f"FileScan API error {resp.status_code} during {context}"
            )
        return resp.json()

    def _handle_response(self, resp: httpx.Response, context: str) -> dict:
        if resp.status_code == 404:
            return {}
        if resp.status_code == 429:
            raise RuntimeError("FileScan rate limit exceeded. Please try again later.")
        if resp.status_code == 401:
            raise RuntimeError("Invalid FileScan API key.")
        if not resp.is_success:
            raise RuntimeError(
                f"FileScan API error {resp.status_code} during {context}"
            )
        return resp.json()

    # -------------------------------------------------------------------------
    # Utility helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _build_form_data(options: dict) -> dict:
        """Convert an options dict to flat string values for multipart form."""
        return {k: str(v) for k, v in options.items() if v is not None}

    @staticmethod
    def _extract_hash(report: dict) -> str:
        """Try several known locations for the file hash."""
        return (
            (report.get("file") or {}).get("hash")
            or report.get("hash")
            or report.get("inputFileHash")
            or ""
        )

    def _compute_threat_score(
        self,
        verdict: str,
        threat_level: int,
        confidence: float,
    ) -> int:
        """
        Map FileScan verdict + threat_level (0-5) + confidence (0-1) to 0-100.
        Mirrors the same scoring philosophy as VirusTotalService.
        """
        base_scores = {
            "MALICIOUS": 90,
            "LIKELY_MALICIOUS": 70,
            "SUSPICIOUS": 45,
            "INFORMATIONAL": 20,
            "NO_THREAT": 5,
            "BENIGN": 0,
            "UNKNOWN": 0,
        }
        base = base_scores.get(verdict.upper(), 0)
        level_bonus = threat_level * 2  # 0–10 extra points
        confidence_multiplier = 0.5 + confidence * 0.5  # 0.5 – 1.0
        return min(100, round((base + level_bonus) * confidence_multiplier))
