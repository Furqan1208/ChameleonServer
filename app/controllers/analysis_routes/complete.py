import json
import uuid
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from app.services.ai_analysis_service import AIAnalysisService
from app.services.cape_analysis_service import CapeAnalysisService
from app.services.database_service import DatabaseService
from app.services.parser_service import ParserService
from app.services.report_structure_service import report_structure_service

from .dependencies import (
    get_ai_analysis_service,
    get_analysis_service,
    get_current_user_id,
    get_db_service,
    get_parser_service,
)

router = APIRouter()


@router.post("/complete", status_code=status.HTTP_201_CREATED)
async def complete_analysis(
    file: UploadFile = File(...),
    model_name: Optional[str] = "gemini-2.5-flash",
    enable_parallel: bool = True,
    max_parallel_sections: int = 4,
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
        print(f"\n{'=' * 70}")
        print("🎯 Starting COMPLETE Analysis")
        print(f"{'=' * 70}")
        print(f"File: {file.filename}")
        print(f"Analysis ID: {analysis_id}")
        print(f"User ID: {user_id}")
        print(f"AI Model: {model_name}")
        print(f"Parallel Mode: {'Enabled' if enable_parallel else 'Disabled'}")
        print(f"{'=' * 70}\n")

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
        print("📊 STEP 1: CAPE Sandbox Analysis...")
        print("-" * 70)
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

        print("✅ CAPE analysis saved to database")

        # Also save to file system (optional backup)
        report_structure_service.save_cape_report(analysis_id, cape_report)

        # Save CAPE report temporarily for parsing
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            json.dump(cape_report, temp_file, indent=2)
            temp_file_path = Path(temp_file.name)
            temp_files.append(temp_file_path)

        # 2. Parse CAPE Report
        print("\n🔧 STEP 2: Parsing CAPE Report...")
        print("-" * 70)
        parsed_results = parser_service.parse_complete_report(
            temp_file_path, structure["parsed"]
        )

        await db_service.save_parsed_results(
            user_id=user_id,
            analysis_id=analysis_id,
            parsed_data=parsed_results,
        )
        sections_parsed = parsed_results["metadata"]["sections_parsed"]
        print(f"✅ Parsed {len(sections_parsed)} sections saved to database")

        # Also save to file system (optional backup)
        report_structure_service.save_parsed_report(analysis_id, parsed_results)

        # 3. AI Analysis
        print("\n🤖 STEP 3: AI Analysis...")
        print("-" * 70)
        ai_analysis_result = await ai_analysis_service.analyze(
            parsed_results=parsed_results,
            model_name=model_name,
            enable_parallel=enable_parallel,
            max_parallel_sections=max_parallel_sections,
        )

        malscore = parsed_results["sections"]["signatures"]["malscore"]

        await db_service.save_ai_results(
            user_id=user_id,
            analysis_id=analysis_id,
            ai_data=ai_analysis_result,
            malscore=malscore,
        )
        print(
            f"✅ AI analysis of {len(ai_analysis_result.get('sections_analyzed', []))} sections saved to database"
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

        print(f"\n{'=' * 70}")
        print("🎉 Analysis COMPLETE!")
        print(f"{'=' * 70}")
        print(f"Analysis ID: {analysis_id}")
        print(f"Threat Score: {malscore:.1f}/10")
        print("Stored in Database: MongoDB")
        print(f"Backup Path: {structure['root']}")
        print(f"{'=' * 70}\n")

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
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"\n❌ Analysis failed: {str(e)}")
        await db_service.update_analysis_status(
            user_id=user_id,
            analysis_id=analysis_id,
            status="failed",
            error=str(e),
        )
        import traceback

        traceback.print_exc()
        raise HTTPException(500, f"Analysis failed: {str(e)}") from e
    finally:
        for temp_file in temp_files:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception:
                pass
