# D:\FYP\ChameleonServer\app\controllers\analysis_routes\parse.py
import json
import uuid
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status

from app.services.ai_analysis_service import AIAnalysisService
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
    get_current_user_id,
    get_db_service,
    get_parser_service,
)

router = APIRouter()

_logger = get_logger("app.controllers.analysis_routes.parse")


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


@router.post("/parse-only", status_code=status.HTTP_201_CREATED)
async def parse_only_analysis(
    file: UploadFile = File(...),
    user_id: str = Depends(get_current_user_id),
    parser_service: ParserService = Depends(get_parser_service),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Parse existing CAPE report only (no AI).
    Stores results in MongoDB with shared analysis_id, scoped to current user.
    """
    analysis_id = str(uuid.uuid4())
    temp_files = []

    try:
        if not file.filename or not file.filename.lower().endswith(".json"):
            raise HTTPException(400, "Only JSON files are supported for parsing")

        _logger.info("%s", "\n" + "=" * 70)
        _logger.info("📄 Starting PARSE-ONLY Analysis")
        _logger.info("File: %s", file.filename)
        _logger.info("Analysis ID: %s", analysis_id)
        _logger.info("User ID: %s", user_id)
        _logger.info("%s", "=" * 70 + "\n")

        await db_service.create_analysis_record(
            user_id=user_id,
            analysis_id=analysis_id,
            filename=file.filename,
            analysis_type="parse_only",
        )

        structure = report_structure_service.create_analysis_structure(
            analysis_id, file.filename
        )

        with NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file_path = Path(temp_file.name)
            temp_files.append(temp_file_path)

        with open(temp_file_path, "r", encoding="utf-8") as f:
            cape_data = json.load(f)

        await db_service.save_cape_results(
            user_id=user_id,
            analysis_id=analysis_id,
            cape_data=cape_data,
        )
        _logger.info("✅ CAPE report saved to database")

        file_hash = _extract_cape_sha256(cape_data)
        threat_intel_context = None
        threat_intel_full_results = None

        if file_hash:
            _logger.info("🔍 STEP 1: Threat Intelligence (before parsing)...")
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

        report_structure_service.save_cape_report(analysis_id, cape_data)

        _logger.info("\n🔧 STEP 1: Parsing CAPE Report...")
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

        file_hash = _extract_cape_sha256(cape_data)
        threat_intel_context = None
        threat_intel_full_results = None

        if file_hash:
            _logger.info("🔍 STEP 1: Threat Intelligence (before parsing)...")
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
        malscore = 0.0
        signatures_section = parsed_results.get("sections", {}).get("signatures", {})
        if isinstance(signatures_section, dict):
            if "malscore" in signatures_section:
                malscore = signatures_section.get("malscore", 0.0) or 0.0
            elif "ai_summary" in signatures_section:
                malscore = signatures_section.get("ai_summary", {}).get("malscore", 0.0) or 0.0
            elif "full" in signatures_section:
                malscore = signatures_section.get("full", {}).get("malscore", 0.0) or 0.0
        _logger.info("\n🔧 STEP 2: Parsing CAPE Report...")

        report_structure_service.save_parsed_report(analysis_id, parsed_results)

        await db_service.update_analysis_status(
            user_id=user_id,
            analysis_id=analysis_id,
            status="complete",
            malscore=malscore,
            sections_parsed=sections_parsed,
        )

        report_structure_service._update_metadata(
            analysis_id,
            {
                "status": "complete",
                "malscore": malscore,
                "analysis_type": "parse_only",
                "completed_at": datetime.now().isoformat(),
                "sections_parsed": sections_parsed,
            },
        )

        _logger.info("%s", "\n" + "=" * 70)
        _logger.info("🎉 Parse-only analysis COMPLETE!")
        _logger.info("Analysis ID: %s", analysis_id)
        _logger.info("Threat Score: %.1f/10", malscore)
        _logger.info("Stored in Database: MongoDB")
        _logger.info("Backup Path: %s", structure["root"])
        _logger.info("%s", "=" * 70 + "\n")

        return {
            "analysis_id": analysis_id,
            "filename": file.filename,
            "status": "complete",
            "message": "CAPE report parsed successfully and stored in database",
            "components": ["cape", "parsed"],
            "malscore": malscore,
            "created_at": datetime.now().isoformat(),
            "storage": "mongodb",
            "backup_path": str(structure["root"]),
            "sections_parsed": sections_parsed,
        }

    except HTTPException:
        raise
    except Exception as e:
        _logger.exception("Parse failed: %s", str(e))
        await db_service.update_analysis_status(
            user_id=user_id,
            analysis_id=analysis_id,
            status="failed",
            error=str(e),
        )
        raise HTTPException(500, f"Parse failed: {str(e)}") from e
    finally:
        for temp_file in temp_files:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception:
                pass


@router.post("/parse-and-ai", status_code=status.HTTP_201_CREATED)
async def parse_and_ai_analysis(
    file: UploadFile = File(...),
    model_name: Optional[str] = Form("gemini-2.5-flash"),
    enable_parallel: bool = Form(True),
    max_parallel_sections: int = Form(4),
    user_id: str = Depends(get_current_user_id),
    parser_service: ParserService = Depends(get_parser_service),
    ai_analysis_service: AIAnalysisService = Depends(get_ai_analysis_service),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Parse existing CAPE report AND perform AI analysis (both together).
    Stores all results in MongoDB with shared analysis_id, scoped to current user.
    """
    analysis_id = str(uuid.uuid4())

    temp_files = []

    try:
        if not file.filename or not file.filename.lower().endswith(".json"):
            raise HTTPException(400, "Only JSON files are supported")

        _logger.info("%s", "\n" + "=" * 70)
        _logger.info("📄🤖 Starting PARSE + AI Analysis")
        _logger.info("File: %s", file.filename)
        _logger.info("Analysis ID: %s", analysis_id)
        _logger.info("User ID: %s", user_id)
        _logger.info("AI Model: %s", model_name)
        _logger.info("Parallel Mode: %s", "Enabled" if enable_parallel else "Disabled")
        _logger.info("%s", "=" * 70 + "\n")

        await db_service.create_analysis_record(
            user_id=user_id,
            analysis_id=analysis_id,
            filename=file.filename,
            analysis_type="parse_and_ai",
            model_name=model_name,
        )

        structure = report_structure_service.create_analysis_structure(
            analysis_id, file.filename
        )

        with NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file_path = Path(temp_file.name)
            temp_files.append(temp_file_path)

        with open(temp_file_path, "r", encoding="utf-8") as f:
            cape_data = json.load(f)

        await db_service.save_cape_results(
            user_id=user_id,
            analysis_id=analysis_id,
            cape_data=cape_data,
        )
        _logger.info("✅ CAPE report saved to database")

        file_hash = _extract_cape_sha256(cape_data)
        threat_intel_context = None
        threat_intel_full_results = None

        if file_hash:
            _logger.info("🔍 STEP 1: Threat Intelligence (before parsing)...")
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

        report_structure_service.save_cape_report(analysis_id, cape_data)

        _logger.info("\n🔧 STEP 1: Parsing CAPE Report...")
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
        _logger.info("✅ Parsed %d sections saved to database", len(sections_parsed))

        report_structure_service.save_parsed_report(analysis_id, parsed_results)

        _logger.info("\n🤖 STEP 3: AI Analysis...")
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
        ai_sections = ai_analysis_result.get("sections_analyzed", [])
        _logger.info("✅ AI analysis of %d sections saved to database", len(ai_sections))

        report_structure_service.save_ai_analysis(analysis_id, ai_analysis_result)

        await db_service.update_analysis_status(
            user_id=user_id,
            analysis_id=analysis_id,
            status="complete",
            malscore=malscore,
            sections_parsed=sections_parsed,
            ai_sections_analyzed=ai_sections,
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

        report_structure_service._update_metadata(
            analysis_id,
            {
                "status": "complete",
                "malscore": malscore,
                "analysis_type": "parse_and_ai",
                "model_used": model_name,
                "completed_at": datetime.now().isoformat(),
                "sections_parsed": sections_parsed,
                "ai_sections_analyzed": ai_sections,
            },
        )

        _logger.info("%s", "\n" + "=" * 70)
        _logger.info("🎉 Parse + AI analysis COMPLETE!")
        _logger.info("Analysis ID: %s", analysis_id)
        _logger.info("Threat Score: %.1f/10", malscore)
        _logger.info("Stored in Database: MongoDB")
        _logger.info("Backup Path: %s", structure["root"])
        _logger.info("%s", "=" * 70 + "\n")

        return {
            "analysis_id": analysis_id,
            "filename": file.filename,
            "status": "complete",
            "message": "Parse+AI analysis completed and stored in database",
            "components": ["cape", "parsed", "ai_analysis"],
            "malscore": malscore,
            "created_at": datetime.now().isoformat(),
            "storage": "mongodb",
            "backup_path": str(structure["root"]),
            "sections_parsed": sections_parsed,
            "ai_sections_analyzed": ai_sections,
            "threat_intel_queried": threat_intel_context is not None,
            "threat_intel_summary": threat_intel_context.get("summary_line", "")
            if threat_intel_context
            else "",
        }

    except HTTPException:
        raise
    except Exception as e:
        _logger.exception("Parse + AI analysis failed: %s", str(e))
        await db_service.update_analysis_status(
            user_id=user_id,
            analysis_id=analysis_id,
            status="failed",
            error=str(e),
        )
        raise HTTPException(500, f"Parse + AI analysis failed: {str(e)}") from e
    finally:
        for temp_file in temp_files:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception:
                pass
