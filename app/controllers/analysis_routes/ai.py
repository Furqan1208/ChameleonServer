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

        print("\n🤖 STEP 1: AI Analysis...")
        print("-" * 70)
        ai_analysis_result = await ai_analysis_service.analyze(
            parsed_results=parsed_data,
            model_name=model_name,
            enable_parallel=enable_parallel,
            max_parallel_sections=max_parallel_sections,
        )

        malscore = parsed_data["sections"]["signatures"]["malscore"]

        await db_service.save_ai_results(
            user_id=user_id,
            analysis_id=analysis_id,
            ai_data=ai_analysis_result,
            malscore=malscore,
        )
        ai_sections = ai_analysis_result.get("sections_analyzed", [])
        print(f"✅ AI analysis of {len(ai_sections)} sections saved to database")

        report_structure_service.save_ai_analysis(analysis_id, ai_analysis_result)

        await db_service.update_analysis_status(
            user_id=user_id,
            analysis_id=analysis_id,
            status="complete",
            malscore=malscore,
            sections_parsed=sections_parsed,
            ai_sections_analyzed=ai_sections,
        )

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
            },
        )

        print(f"\n{'=' * 70}")
        print("🎉 AI-only analysis COMPLETE!")
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
            "message": "AI analysis completed successfully and stored in database",
            "components": ["parsed", "ai_analysis"],
            "malscore": malscore,
            "created_at": datetime.now().isoformat(),
            "storage": "mongodb",
            "backup_path": str(structure["root"]),
            "sections_parsed": sections_parsed,
            "ai_sections_analyzed": ai_sections,
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
