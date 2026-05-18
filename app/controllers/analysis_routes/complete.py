import json
import uuid
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status

from app.services.ai_analysis_service import AIAnalysisService
from app.services.cape_analysis_service import CapeAnalysisService
from app.services.database_service import DatabaseService
from app.services.parser_service import ParserService
from app.services.report_structure_service import report_structure_service
from app.services.threat_intel_Integerations.unified_service import (
    UnifiedThreatIntelService,
)
from app.utils.logger import get_logger

from ._analysis_helpers import extract_malscore

from .dependencies import (
    get_ai_analysis_service,
    get_analysis_service,
    get_current_user_id,
    get_db_service,
    get_parser_service,
)

router = APIRouter()

_logger = get_logger("app.controllers.analysis_routes.complete")


def _extract_cape_sha256(cape_data: dict) -> Optional[str]:
    """Extract the best available SHA256 from a CAPE report before parsing."""
    if not isinstance(cape_data, dict):
        return None

    metadata = cape_data.get("metadata", {})
    if metadata.get("sha256"):
        return metadata["sha256"]

    sections = cape_data.get("sections", {})
    signatures = sections.get("signatures", {})
    if signatures.get("sha256"):
        return signatures["sha256"]

    target = cape_data.get("target", {})
    if isinstance(target, dict):
        target_file = target.get("file", {})
        if isinstance(target_file, dict) and target_file.get("sha256"):
            return target_file["sha256"]

    return None


@router.post("/complete", status_code=status.HTTP_201_CREATED)
async def complete_analysis(
    file: UploadFile = File(...),
    model_name: Optional[str] = Form("gemini-2.5-flash"),
    enable_parallel: bool = Form(True),
    max_parallel_sections: int = Form(4),
    user_id: str = Depends(get_current_user_id),
    analysis_service: CapeAnalysisService = Depends(get_analysis_service),
    parser_service: ParserService = Depends(get_parser_service),
    ai_analysis_service: AIAnalysisService = Depends(get_ai_analysis_service),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Complete malware analysis: File → CAPE → Parse → AI
    Stores all results in MongoDB with shared analysis_id, scoped to current user.
    Auth is verified once by the parent router — user object is reused here via
    FastAPI's dependency caching (no extra DB call).
    """
    analysis_id = str(uuid.uuid4())
    temp_files = []

    try:
        _logger.info("%s", "\n" + "=" * 70)
        _logger.info("Starting COMPLETE Analysis")
        _logger.info("File: %s", file.filename)
        _logger.info("Analysis ID: %s", analysis_id)
        _logger.info("User ID: %s", user_id)
        _logger.info("AI Model: %s", model_name)
        _logger.info("Parallel Mode: %s", 'Enabled' if enable_parallel else 'Disabled')
        _logger.info("%s", "=" * 70 + "\n")

        # Create initial analysis record in database, associated with user
        await db_service.create_analysis_record(
            user_id=user_id,
            analysis_id=analysis_id,
            filename=file.filename or "unknown_file",
            analysis_type="complete",
            model_name=model_name,
        )

        # Create folder structure (for backward compatibility/backup)
        structure = report_structure_service.create_analysis_structure(
            analysis_id, file.filename or "unknown_file"
        )

        # 1. CAPE Analysis
        _logger.info("STEP 1: CAPE Sandbox Analysis...")
        _logger.info("%s", "-" * 70)
        cape_report = await analysis_service.upload_and_analyze(
            user_id=user_id,
            analysis_id=analysis_id,
            file=file,
        )

        if not cape_report:
            await db_service.update_analysis_status(
                user_id=user_id,
                analysis_id=analysis_id,
                status="failed",
                error="CAPE analysis failed",
            )
            raise HTTPException(500, "CAPE analysis failed - no report returned")

        # Save CAPE report to database
        await db_service.save_cape_results(
            user_id=user_id,
            analysis_id=analysis_id,
            cape_data=cape_report,
        )
        _logger.info("✅ CAPE analysis saved to database")

        file_hash = _extract_cape_sha256(cape_report)
        threat_intel_context = None
        threat_intel_full_results = None

        if file_hash:
            _logger.info("🔍 STEP 2: Threat Intelligence (before parsing)...")
            _logger.info("Hash: %s", file_hash)
            try:
                ti_service = UnifiedThreatIntelService()
                threat_intel_full_results = await ti_service.unified_search(file_hash)
                threat_intel_context = ti_service.minimal_summary_for_ai(
                    threat_intel_full_results.get("results", {})
                )

                try:
                    await db_service.save_threat_intel(
                        user_id=user_id,
                        analysis_id=analysis_id,
                        threat_intel_data=threat_intel_full_results,
                    )
                    _logger.info("✅ Threat Intel saved to database")
                except Exception as e:
                    _logger.warning("Threat Intel DB save failed: %s", str(e))

                _logger.info(
                    "✅ Threat Intel gathered: %s",
                    threat_intel_context.get("summary_line", "Summary unavailable")
                    if threat_intel_context
                    else "Summary unavailable",
                )
            except Exception as e:
                _logger.warning(
                    "Threat Intel gathering failed before parsing: %s", str(e)
                )
        else:
            _logger.warning("No file hash found in CAPE report - skipping threat intel")

        # Also save to file system (optional backup)
        report_structure_service.save_cape_report(analysis_id, cape_report)

        # Save CAPE report temporarily for parsing
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            json.dump(cape_report, temp_file, indent=2)
            temp_file_path = Path(temp_file.name)
            temp_files.append(temp_file_path)

        # 3. Parse CAPE Report
        _logger.info("STEP 3: Parsing CAPE Report...")
        _logger.info("%s", "-" * 70)
        parsed_results = parser_service.parse_complete_report(
            temp_file_path, structure["parsed"]
        )

        await db_service.save_parsed_results(
            user_id=user_id,
            analysis_id=analysis_id,
            parsed_data=parsed_results,
        )
        sections_parsed = parsed_results["metadata"]["sections_parsed"]
        _logger.info("Parsed %d sections saved to database", len(sections_parsed))

        # Also save to file system (optional backup)
        report_structure_service.save_parsed_report(analysis_id, parsed_results)

        # 4. AI Analysis
        _logger.info("STEP 4: AI Analysis...")
        _logger.info("%s", "-" * 70)
        ai_analysis_result = await ai_analysis_service.analyze(
            parsed_results=parsed_results,
            model_name=model_name,
            enable_parallel=enable_parallel,
            max_parallel_sections=max_parallel_sections,
            threat_intel_context=threat_intel_context,
        )

        malscore = extract_malscore(parsed_results)

        await db_service.save_ai_results(
            user_id=user_id,
            analysis_id=analysis_id,
            ai_data=ai_analysis_result,
            malscore=malscore,
        )
        _logger.info(
            "AI analysis of %d sections saved to database",
            len(ai_analysis_result.get("sections_analyzed", [])),
        )

        # Also save to file system (optional backup)
        report_structure_service.save_ai_analysis(analysis_id, ai_analysis_result)

        # Update final status
        await db_service.update_analysis_status(
            user_id=user_id,
            analysis_id=analysis_id,
            status="complete",
            malscore=malscore,
            sections_parsed=sections_parsed,
            ai_sections_analyzed=ai_analysis_result.get("sections_analyzed", []),
            threat_intel={
                "hash_queried": file_hash,
                "sources_checked": len(threat_intel_full_results.get("results", {}))
                if threat_intel_full_results
                else 0,
                "summary": threat_intel_context.get("summary_line", "")
                if threat_intel_context
                else "",
            }
            if threat_intel_context
            else None,
        )

        # Update file system metadata
        report_structure_service._update_metadata(
            analysis_id,
            {
                "status": "complete",
                "malscore": malscore,
                "analysis_type": "complete",
                "model_used": model_name,
                "completed_at": datetime.now().isoformat(),
                "sections_parsed": sections_parsed,
                "ai_sections_analyzed": ai_analysis_result.get("sections_analyzed", []),
            },
        )

        _logger.info("%s", "\n" + "=" * 70)
        _logger.info("Analysis COMPLETE!")
        _logger.info("Analysis ID: %s", analysis_id)
        _logger.info("Threat Score: %.1f/10", malscore)
        _logger.info("Stored in Database: MongoDB")
        _logger.info("Backup Path: %s", structure["root"])
        _logger.info("%s", "=" * 70 + "\n")

        return {
            "analysis_id": analysis_id,
            "filename": file.filename,
            "status": "complete",
            "message": "Complete analysis finished successfully and stored in database",
            "components": ["cape", "parsed", "ai_analysis"],
            "malscore": malscore,
            "created_at": datetime.now().isoformat(),
            "storage": "mongodb",
            "backup_path": str(structure["root"]),
            "sections_parsed": sections_parsed,
            "ai_sections_analyzed": ai_analysis_result.get("sections_analyzed", []),
            "threat_intel_queried": threat_intel_context is not None,
            "threat_intel_summary": threat_intel_context.get("summary_line", "")
            if threat_intel_context
            else "",
        }

    except HTTPException:
        raise
    except Exception as e:
        _logger.exception("Analysis failed: %s", str(e))
        await db_service.update_analysis_status(
            user_id=user_id,
            analysis_id=analysis_id,
            status="failed",
            error=str(e),
        )
        raise HTTPException(500, f"Analysis failed: {str(e)}") from e
    finally:
        for temp_file in temp_files:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception:
                pass
