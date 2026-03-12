# app/controllers/threat_intel_routes.py
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel

from app.dependencies.user_dependency import get_current_user
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
from app.services.threat_intel_Integerations.urlhaus_service import URLhausService
from app.services.threat_intel_Integerations.unified_service import (
    UnifiedThreatIntelService,
)
from app.services.threat_intel_Integerations.virustotal_service import VirusTotalService

router = APIRouter(
    prefix="/threat-intel",
    tags=["threat-intel"],
    dependencies=[Depends(get_current_user)],
)

# ── Schemas ───────────────────────────────────────────────────────────────────


class VTScanRequest(BaseModel):
    indicator: str
    type: str  # hash | ip | domain | url
    include_relationships: bool = False


class MBSearchRequest(BaseModel):
    query: str
    type: str = "hash"
    limit: int = 10


class OTXScanRequest(BaseModel):
    indicator: str
    type: str  # ip | domain | url | hash


class ThreatFoxSearchRequest(BaseModel):
    indicator: str


class UnifiedSearchRequest(BaseModel):
    indicator: str


class FileScanUrlRequest(BaseModel):
    url: str
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    propagate_tags: Optional[bool] = None
    # Pass-through scan options
    osint: Optional[bool] = None
    extended_osint: Optional[bool] = None
    resolve_domains: Optional[bool] = None
    whois: Optional[bool] = None
    url_analysis: Optional[bool] = None


class FileScanSimilarityRequest(BaseModel):
    hash: str
    min_similarity: float = 0.0
    verdict: Optional[str] = None
    tags: Optional[List[str]] = None


class HAScanRequest(BaseModel):
    indicator: str
    type: str = "hash"  # only 'hash' is supported
    include_summary: bool = True


class URLhausRequest(BaseModel):
    indicator: str


# ── Dependencies ──────────────────────────────────────────────────────────────


def get_vt_service() -> VirusTotalService:
    return VirusTotalService()


def get_mb_service() -> MalwareBazaarService:
    return MalwareBazaarService()


def get_otx_service() -> AlienVaultOTXService:
    return AlienVaultOTXService()


def get_abuseipdb_service() -> AbuseIPDBService:
    return AbuseIPDBService()


def get_threatfox_service() -> ThreatFoxService:
    return ThreatFoxService()


def get_urlhaus_service() -> URLhausService:
    return URLhausService()


def get_unified_service() -> UnifiedThreatIntelService:
    return UnifiedThreatIntelService()


def get_filescan_service() -> FileScanService:
    return FileScanService()


def get_ha_service() -> HybridAnalysisService:
    return HybridAnalysisService()


# ── VirusTotal ────────────────────────────────────────────────────────────────


@router.post("/virustotal/scan")
async def scan_virustotal(
    request: VTScanRequest,
    svc: VirusTotalService = Depends(get_vt_service),
):
    try:
        result = await svc.scan_indicator(
            request.indicator, request.type, request.include_relationships
        )
        return {"status": "success", "data": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.get("/virustotal/hash/{hash_value}")
async def get_vt_hash(
    hash_value: str,
    include_relationships: bool = Query(False),
    svc: VirusTotalService = Depends(get_vt_service),
):
    try:
        result = await svc.scan_indicator(hash_value, "hash", include_relationships)
        return {"status": "success", "data": result}
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


# ── MalwareBazaar ─────────────────────────────────────────────────────────────


@router.post("/malwarebazaar/search")
async def search_malwarebazaar(
    request: MBSearchRequest,
    svc: MalwareBazaarService = Depends(get_mb_service),
):
    try:
        result = await svc.search_indicator(request.query, request.type, request.limit)
        return {"status": "success", "data": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/malwarebazaar/recent")
async def get_mb_recent(
    limit: int = Query(10, le=100),
    svc: MalwareBazaarService = Depends(get_mb_service),
):
    samples = await svc.get_recent_samples(limit)
    return {"status": "success", "data": samples}


# ── AlienVault OTX ────────────────────────────────────────────────────────────


@router.post("/alienvault/scan")
async def scan_alienvault(
    request: OTXScanRequest,
    svc: AlienVaultOTXService = Depends(get_otx_service),
):
    try:
        result = await svc.scan_indicator(request.indicator, request.type)
        return {"status": "success", "data": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────


@router.get("/abuseipdb/check/{ip}")
async def check_abuseipdb(
    ip: str,
    max_age_days: int = Query(90, le=365),
    svc: AbuseIPDBService = Depends(get_abuseipdb_service),
):
    try:
        result = await svc.check_ip(ip, max_age_days)
        return {"status": "success", "data": result}
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.post("/abuseipdb/check")
async def check_abuseipdb_post(
    body: dict,
    svc: AbuseIPDBService = Depends(get_abuseipdb_service),
):
    ip = body.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="ip field required")
    try:
        result = await svc.check_ip(ip, body.get("max_age_days", 90))
        return {"status": "success", "data": result}
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


# ── ThreatFox ─────────────────────────────────────────────────────────────────


@router.post("/threatfox/search")
async def search_threatfox(
    request: ThreatFoxSearchRequest,
    svc: ThreatFoxService = Depends(get_threatfox_service),
):
    try:
        result = await svc.search_indicator(request.indicator)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/threatfox/recent")
async def get_threatfox_recent(
    days: int = Query(3, le=30),
    limit: int = Query(20, le=100),
    svc: ThreatFoxService = Depends(get_threatfox_service),
):
    iocs = await svc.get_recent_iocs(days, limit)
    return {"status": "success", "data": iocs}


@router.get("/threatfox/malware-list")
async def get_threatfox_malware_list(
    svc: ThreatFoxService = Depends(get_threatfox_service),
):
    data = await svc.get_malware_list()
    return {"status": "success", "data": data}


# ── URLhaus ───────────────────────────────────────────────────────────────────


@router.post("/urlhaus/check")
async def check_urlhaus(
    request: URLhausRequest,
    svc: URLhausService = Depends(get_urlhaus_service),
):
    """
    Check an indicator in URLhaus (auto-detects type: url, hash, host, or tag)
    """
    try:
        result = await svc.check_indicator(request.indicator)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/urlhaus/url")
async def check_urlhaus_url(
    request: URLhausRequest,
    svc: URLhausService = Depends(get_urlhaus_service),
):
    """Check a URL in URLhaus"""
    try:
        result = await svc.check_url(request.indicator)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/urlhaus/hash")
async def check_urlhaus_hash(
    request: URLhausRequest,
    svc: URLhausService = Depends(get_urlhaus_service),
):
    """Check a hash (payload) in URLhaus"""
    try:
        result = await svc.check_hash(request.indicator)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/urlhaus/host")
async def check_urlhaus_host(
    request: URLhausRequest,
    svc: URLhausService = Depends(get_urlhaus_service),
):
    """Check a host in URLhaus"""
    try:
        result = await svc.check_host(request.indicator)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/urlhaus/tag")
async def check_urlhaus_tag(
    request: URLhausRequest,
    svc: URLhausService = Depends(get_urlhaus_service),
):
    """Check a tag in URLhaus"""
    try:
        result = await svc.check_tag(request.indicator)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


# ── FileScan ──────────────────────────────────────────────────────────────────


@router.post("/filescan/upload")
async def filescan_upload_file(
    file: UploadFile = File(...),
    description: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),  # comma-separated
    osint: Optional[bool] = Query(None),
    extended_osint: Optional[bool] = Query(None),
    resolve_domains: Optional[bool] = Query(None),
    whois: Optional[bool] = Query(None),
    svc: FileScanService = Depends(get_filescan_service),
):
    """Upload a file for sandboxed analysis. Returns flow_id for polling."""
    try:
        content = await file.read()
        options: dict = {}
        if osint is not None:
            options["osint"] = osint
        if extended_osint is not None:
            options["extended_osint"] = extended_osint
        if resolve_domains is not None:
            options["resolve_domains"] = resolve_domains
        if whois is not None:
            options["whois"] = whois
        if description:
            options["description"] = description
        if tags:
            options["tags"] = tags

        result = await svc.upload_file(content, file.filename or "upload", options)
        return {"status": "success", "data": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.post("/filescan/scan-url")
async def filescan_scan_url(
    request: FileScanUrlRequest,
    svc: FileScanService = Depends(get_filescan_service),
):
    """Submit a URL for analysis. Returns flow_id for polling."""
    try:
        options: dict = {}
        for field in (
            "description",
            "osint",
            "extended_osint",
            "resolve_domains",
            "whois",
            "url_analysis",
        ):
            val = getattr(request, field, None)
            if val is not None:
                options[field] = val
        if request.tags:
            options["tags"] = ",".join(request.tags)
        if request.propagate_tags is not None:
            options["propagate_tags"] = request.propagate_tags

        result = await svc.scan_url(request.url, options)
        return {"status": "success", "data": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.get("/filescan/status/{flow_id}")
async def filescan_status(
    flow_id: str,
    filters: Optional[str] = Query(None),  # comma-separated filter names
    svc: FileScanService = Depends(get_filescan_service),
):
    """Poll scan status. When state == 'finished', reports are ready."""
    try:
        filter_list = filters.split(",") if filters else None
        result = await svc.get_scan_status(flow_id, filter_list)
        return {"status": "success", "data": result}
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.get("/filescan/report/{report_id}/{file_hash}")
async def filescan_report(
    report_id: str,
    file_hash: str,
    filters: Optional[str] = Query(None),
    svc: FileScanService = Depends(get_filescan_service),
):
    """Fetch a specific report by report_id + file_hash."""
    try:
        filter_list = filters.split(",") if filters else None
        result = await svc.get_report(report_id, file_hash, filter_list)
        if not result:
            raise HTTPException(status_code=404, detail="Report not found")
        return {"status": "success", "data": result}
    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.get("/filescan/analysis/{flow_id}")
async def filescan_full_analysis(
    flow_id: str,
    svc: FileScanService = Depends(get_filescan_service),
):
    """
    Get a complete, normalised AnalysisResult for a finished scan.
    Raises 425 if the scan is not yet complete.
    """
    try:
        result = await svc.get_full_analysis(flow_id)
        return {"status": "success", "data": result}
    except RuntimeError as e:
        msg = str(e)
        if "not finished" in msg.lower():
            raise HTTPException(status_code=425, detail=msg) from e
        raise HTTPException(status_code=502, detail=msg) from e


@router.post("/filescan/similarity")
async def filescan_similarity(
    request: FileScanSimilarityRequest,
    svc: FileScanService = Depends(get_filescan_service),
):
    """Find files similar to a given hash."""
    try:
        result = await svc.similarity_search(
            request.hash,
            request.min_similarity,
            request.verdict,
            request.tags,
        )
        return {"status": "success", "data": result}
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


# ── Hybrid Analysis ───────────────────────────────────────────────────────────


@router.post("/hybrid-analysis/scan")
async def ha_scan(
    request: HAScanRequest,
    svc: HybridAnalysisService = Depends(get_ha_service),
):
    """Look up a hash (MD5 / SHA1 / SHA256 / SHA512) in Hybrid Analysis."""
    try:
        result = await svc.scan_indicator(
            indicator=request.indicator,
            ioc_type=request.type,
            include_summary=request.include_summary,
        )
        return {"status": "success", "data": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.get("/hybrid-analysis/hash/{hash_value}")
async def ha_hash_lookup(
    hash_value: str,
    include_summary: bool = Query(True),
    svc: HybridAnalysisService = Depends(get_ha_service),
):
    """Convenience GET endpoint for hash lookups."""
    try:
        result = await svc.scan_indicator(
            indicator=hash_value,
            ioc_type="hash",
            include_summary=include_summary,
        )
        return {"status": "success", "data": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.get("/hybrid-analysis/feed")
async def ha_threat_feed(
    limit: int = Query(50, le=200),
    svc: HybridAnalysisService = Depends(get_ha_service),
):
    """Fetch recent detonation results from the HA threat feed."""
    try:
        result = await svc.get_threat_feed(limit)
        return {"status": "success", "data": result}
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.get("/hybrid-analysis/feed/quick-scan")
async def ha_quick_scan_feed(
    limit: int = Query(50, le=200),
    svc: HybridAnalysisService = Depends(get_ha_service),
):
    """Fetch the HA quick-scan feed."""
    try:
        result = await svc.get_quick_scan_feed(limit)
        return {"status": "success", "data": result}
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.get("/hybrid-analysis/report/{report_id}/summary")
async def ha_report_summary(
    report_id: str,
    svc: HybridAnalysisService = Depends(get_ha_service),
):
    """Fetch a detailed report summary by report/job ID."""
    try:
        result = await svc.get_report_summary(report_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Report not found")
        return {"status": "success", "data": result}
    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.get("/hybrid-analysis/report/{report_id}/state")
async def ha_report_state(
    report_id: str,
    svc: HybridAnalysisService = Depends(get_ha_service),
):
    """Fetch report state by report/job ID."""
    try:
        result = await svc.get_report_state(report_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Report not found")
        return {"status": "success", "data": result}
    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.get("/hybrid-analysis/report/{report_id}")
async def ha_report_details(
    report_id: str,
    svc: HybridAnalysisService = Depends(get_ha_service),
):
    """Fetch full report details by report/job ID."""
    try:
        result = await svc.get_report_details(report_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Report not found")
        return {"status": "success", "data": result}
    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


# ── Unified Search ────────────────────────────────────────────────────────────


@router.post("/unified/search")
async def unified_search(
    request: UnifiedSearchRequest,
    svc: UnifiedThreatIntelService = Depends(get_unified_service),
):
    """Auto-detect input type and fan out to all relevant threat intel services."""
    try:
        result = await svc.unified_search(request.indicator)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/unified/detect-type")
async def detect_input_type(
    indicator: str = Query(...),
    svc: UnifiedThreatIntelService = Depends(get_unified_service),
):
    return {"indicator": indicator, "type": svc.detect_input_type(indicator)}
