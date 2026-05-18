# D:\FYP\ChameleonServer\app\controllers\analysis_routes\ai.py
import json
import uuid
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from app.services.ai_analysis_service import AIAnalysisService
from app.services.database_service import DatabaseService
from app.services.parser_service import ParserService
from app.services.report_structure_service import report_structure_service
from app.services.threat_intel_Integerations.unified_service import (
    UnifiedThreatIntelService,
)

from ._analysis_helpers import extract_malscore

from .dependencies import (
    get_ai_analysis_service,
    get_current_user_id,
    get_db_service,
    get_parser_service,
)

router = APIRouter()


@router.post("/ai-only", status_code=status.HTTP_201_CREATED)
async def ai_only_analysis(
    file: UploadFile = File(...),
    model_name: Optional[str] = "gemini-2.5-flash",
    enable_parallel: bool = True,
    max_parallel_sections: int = 4,
    user_id: str = Depends(get_current_user_id),
    parser_service: ParserService = Depends(get_parser_service),
    ai_analysis_service: AIAnalysisService = Depends(get_ai_analysis_service),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    AI analysis on already parsed data.
    Stores results in MongoDB with shared analysis_id, scoped to current user.
    """
    analysis_id = str(uuid.uuid4())
    temp_files = []

    try:
        if not file.filename or not file.filename.lower().endswith(".json"):
            raise HTTPException(400, "Only JSON files are supported")

        print(f"\n{'=' * 70}")
        print("🤖 Starting AI-ONLY Analysis")
        print(f"{'=' * 70}")
        print(f"File: {file.filename}")
        print(f"Analysis ID: {analysis_id}")
        print(f"User ID: {user_id}")
        print(f"AI Model: {model_name}")
        print(f"Parallel Mode: {'Enabled' if enable_parallel else 'Disabled'}")
        print(f"{'=' * 70}\n")

        await db_service.create_analysis_record(
            user_id,
            analysis_id=analysis_id,
            filename=file.filename,
            analysis_type="ai_only",
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
            parsed_data = json.load(f)

        if "sections" not in parsed_data or "metadata" not in parsed_data:
            await db_service.update_analysis_status(
                user_id=user_id,
                analysis_id=analysis_id,
                status="failed",
                error="Invalid parsed data format",
            )
            raise HTTPException(
                400, "File must be in parsed format (with 'sections' and 'metadata')"
            )

        await db_service.save_parsed_results(
            user_id=user_id,
            analysis_id=analysis_id,
            parsed_data=parsed_data,
        )
        sections_parsed = parsed_data["metadata"]["sections_parsed"]
        print(
            f"✅ Parsed data loaded and saved to database ({len(sections_parsed)} sections)"
        )

        report_structure_service.save_parsed_report(analysis_id, parsed_data)

        # =====================================================================
        # ✅ NEW: Gather Threat Intelligence BEFORE AI Analysis
        # =====================================================================
        file_hash = None
        threat_intel_context = None
        threat_intel_full_results = None

        # Try multiple locations for the file hash
        if "metadata" in parsed_data and "sha256" in parsed_data["metadata"]:
            file_hash = parsed_data["metadata"]["sha256"]
        elif (
            "sections" in parsed_data
            and "signatures" in parsed_data["sections"]
            and "sha256" in parsed_data["sections"]["signatures"]
        ):
            file_hash = parsed_data["sections"]["signatures"]["sha256"]
        elif "target" in parsed_data and "file" in parsed_data["target"]:
            target_file = parsed_data["target"]["file"]
            if "sha256" in target_file:
                file_hash = target_file["sha256"]

        if file_hash:
            print(f"\n🔍 STEP 0: Gathering Threat Intelligence...")
            print("-" * 70)
            print(f"Hash: {file_hash}")
            try:
                ti_service = UnifiedThreatIntelService()
                threat_intel_full_results = await ti_service.unified_search(file_hash)

                # Create compact summary for AI consumption
                threat_intel_context = ti_service.minimal_summary_for_ai(
                    threat_intel_full_results.get("results", {})
                )

                # Save threat intel results to database
                try:
                    await db_service.save_threat_intel(
                        user_id=user_id,
                        analysis_id=analysis_id,
                        threat_intel_data=threat_intel_full_results,
                    )
                    print("✅ Threat Intel saved to database")
                except Exception as e:
                    print(f"⚠️  Failed to save threat intel to DB: {e}")
                    # Continue even if save fails - we still have the context for AI

                # Print summary for logging
                print(f"✅ Threat Intel gathered:")
                if "virustotal" in threat_intel_context:
                    vt = threat_intel_context["virustotal"]
                    print(
                        f"   VirusTotal: {'Found' if vt.get('found') else 'Not Found'} | "
                        f"Score: {vt.get('threat_score', 0)} | "
                        f"Detections: {vt.get('detection_stats', {})}"
                    )
                if "malwarebazaar" in threat_intel_context:
                    mb = threat_intel_context["malwarebazaar"]
                    print(
                        f"   MalwareBazaar: {'Found' if mb.get('found') else 'Not Found'} | "
                        f"Samples: {mb.get('total', 0)}"
                    )
                if "hybrid_analysis" in threat_intel_context:
                    ha = threat_intel_context["hybrid_analysis"]
                    print(
                        f"   Hybrid Analysis: {'Found' if ha.get('found') else 'Not Found'} | "
                        f"Verdict: {ha.get('verdict', 'N/A')} | "
                        f"Score: {ha.get('threat_score', 0)}"
                    )
                if "alienvault" in threat_intel_context:
                    otx = threat_intel_context["alienvault"]
                    print(
                        f"   AlienVault OTX: {'Found' if otx.get('found') else 'Not Found'} | "
                        f"Pulses: {otx.get('pulse_count', 0)} | "
                        f"Reputation: {otx.get('reputation', 0)}"
                    )
                if "summary_line" in threat_intel_context:
                    print(f"   Summary: {threat_intel_context['summary_line']}")
                print("-" * 70)
            except Exception as e:
                print(f"⚠️  Threat Intel gathering failed: {e}")
                print("   Continuing with AI analysis without threat intel context...")
                threat_intel_context = None
        else:
            print("\n⚠️  No file hash found in parsed data - skipping threat intel")
            print("-" * 70)

        # =====================================================================
        # AI Analysis (now with threat intel context)
        # =====================================================================
        print("\n🤖 STEP 1: AI Analysis...")
        print("-" * 70)

        ai_analysis_result = await ai_analysis_service.analyze(
            parsed_results=parsed_data,
            model_name=model_name,
            enable_parallel=enable_parallel,
            max_parallel_sections=max_parallel_sections,
            threat_intel_context=threat_intel_context,  # ✅ Pass threat intel to AI
        )

        malscore = extract_malscore(parsed_data)

        await db_service.save_ai_results(
            user_id=user_id,
            analysis_id=analysis_id,
            ai_data=ai_analysis_result,
            malscore=malscore,
        )
        ai_sections = ai_analysis_result.get("sections_analyzed", [])
        print(f"✅ AI analysis of {len(ai_sections)} sections saved to database")

        report_structure_service.save_ai_analysis(analysis_id, ai_analysis_result)

        # Update status with threat intel info
        status_update = {
            "user_id": user_id,
            "analysis_id": analysis_id,
            "status": "complete",
            "malscore": malscore,
            "sections_parsed": sections_parsed,
            "ai_sections_analyzed": ai_sections,
        }

        # Add threat intel status if available
        if threat_intel_context:
            status_update["threat_intel"] = {
                "hash_queried": file_hash,
                "sources_checked": len(threat_intel_full_results.get("results", {})),
                "summary": threat_intel_context.get("summary_line", ""),
            }

        await db_service.update_analysis_status(**status_update)

        report_structure_service._update_metadata(
            analysis_id,
            {
                "status": "complete",
                "malscore": malscore,
                "analysis_type": "ai_only",
                "model_used": model_name,
                "completed_at": datetime.now().isoformat(),
                "sections_parsed": sections_parsed,
                "ai_sections_analyzed": ai_sections,
                "threat_intel_used": threat_intel_context is not None,
                "threat_intel_hash": file_hash,
            },
        )

        print(f"\n{'=' * 70}")
        print("🎉 AI-only analysis COMPLETE!")
        print(f"{'=' * 70}")
        print(f"Analysis ID: {analysis_id}")
        print(f"Threat Score: {malscore:.1f}/10")
        if threat_intel_context:
            print(f"Threat Intel: {threat_intel_context.get('summary_line', 'N/A')}")
        print("Stored in Database: MongoDB")
        print(f"Backup Path: {structure['root']}")
        print(f"{'=' * 70}\n")

        return {
            "analysis_id": analysis_id,
            "filename": file.filename,
            "status": "complete",
            "message": "AI analysis completed successfully and stored in database",
            "components": (
                ["parsed", "threat_intel", "ai_analysis"]
                if threat_intel_context
                else ["parsed", "ai_analysis"]
            ),
            "malscore": malscore,
            "created_at": datetime.now().isoformat(),
            "storage": "mongodb",
            "backup_path": str(structure["root"]),
            "sections_parsed": sections_parsed,
            "ai_sections_analyzed": ai_sections,
            "threat_intel_queried": threat_intel_context is not None,
            "threat_intel_summary": (
                threat_intel_context.get("summary_line", "")
                if threat_intel_context
                else ""
            ),
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"\n❌ AI analysis failed: {str(e)}")
        await db_service.update_analysis_status(
            user_id=user_id,
            analysis_id=analysis_id,
            status="failed",
            error=str(e),
        )
        raise HTTPException(500, f"AI analysis failed: {str(e)}") from e
    finally:
        for temp_file in temp_files:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception:
                pass