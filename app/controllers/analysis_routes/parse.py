# D:\FYP\ChameleonServer\app\controllers\analysis_routes\parse.py
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

from .dependencies import get_ai_analysis_service, get_db_service, get_parser_service

router = APIRouter()


@router.post("/parse-only", status_code=status.HTTP_201_CREATED)
async def parse_only_analysis(
    file: UploadFile = File(...),
    parser_service: ParserService = Depends(get_parser_service),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Parse existing CAPE report only (no AI)
    Stores results in MongoDB with shared analysis_id
    """
    analysis_id = str(uuid.uuid4())
    temp_files = []

    try:
        if not file.filename or not file.filename.lower().endswith(".json"):
            raise HTTPException(400, "Only JSON files are supported for parsing")

        print(f"\n{'=' * 70}")
        print("📄 Starting PARSE-ONLY Analysis")
        print(f"{'=' * 70}")
        print(f"File: {file.filename}")
        print(f"Analysis ID: {analysis_id}")
        print(f"{'=' * 70}\n")

        # Create initial analysis record in database
        await db_service.create_analysis_record(
            analysis_id=analysis_id, filename=file.filename, analysis_type="parse_only"
        )

        # Create folder structure (for backward compatibility/backup)
        structure = report_structure_service.create_analysis_structure(
            analysis_id, file.filename
        )

        # Save uploaded CAPE report temporarily
        with NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file_path = Path(temp_file.name)
            temp_files.append(temp_file_path)

        # Load and save CAPE data
        with open(temp_file_path, "r", encoding="utf-8") as f:
            cape_data = json.load(f)

        # Save to database
        await db_service.save_cape_results(analysis_id, cape_data)
        print("✅ CAPE report saved to database")

        report_structure_service.save_cape_report(analysis_id, cape_data)

        # Parse the report
        print("\n🔧 STEP 1: Parsing CAPE Report...")
        print("-" * 70)
        parsed_results = parser_service.parse_complete_report(
            temp_file_path, structure["parsed"]
        )

        await db_service.save_parsed_results(analysis_id, parsed_results)
        sections_parsed = parsed_results["metadata"]["sections_parsed"]
        print(f"✅ Parsed {len(sections_parsed)} sections saved to database")

        report_structure_service.save_parsed_report(analysis_id, parsed_results)

        await db_service.update_analysis_status(
            analysis_id, "complete", sections_parsed=sections_parsed
        )

        report_structure_service._update_metadata(
            analysis_id,
            {
                "status": "complete",
                "analysis_type": "parse_only",
                "completed_at": datetime.now().isoformat(),
                "sections_parsed": sections_parsed,
            },
        )

        print(f"\n{'=' * 70}")
        print("🎉 Parse-only analysis COMPLETE!")
        print(f"{'=' * 70}")
        print(f"Analysis ID: {analysis_id}")
        print("Stored in Database: MongoDB")
        print(f"Backup Path: {structure['root']}")
        print(f"{'=' * 70}\n")

        return {
            "analysis_id": analysis_id,
            "filename": file.filename,
            "status": "complete",
            "message": "CAPE report parsed successfully and stored in database",
            "components": ["cape", "parsed"],
            "created_at": datetime.now().isoformat(),
            "storage": "mongodb",
            "backup_path": str(structure["root"]),
            "sections_parsed": sections_parsed,
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"\n❌ Parse failed: {str(e)}")
        await db_service.update_analysis_status(analysis_id, "failed", error=str(e))
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
    model_name: Optional[str] = "gemini-2.5-flash",
    enable_parallel: bool = True,
    max_parallel_sections: int = 4,
    parser_service: ParserService = Depends(get_parser_service),
    ai_analysis_service: AIAnalysisService = Depends(get_ai_analysis_service),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Parse existing CAPE report AND perform AI analysis (both together)
    Stores all results in MongoDB with shared analysis_id
    """
    analysis_id = str(uuid.uuid4())
    temp_files = []

    try:
        if not file.filename or not file.filename.lower().endswith(".json"):
            raise HTTPException(400, "Only JSON files are supported")

        print(f"\n{'=' * 70}")
        print("📄🤖 Starting PARSE + AI Analysis")
        print(f"{'=' * 70}")
        print(f"File: {file.filename}")
        print(f"Analysis ID: {analysis_id}")
        print(f"AI Model: {model_name}")
        print(f"Parallel Mode: {'Enabled' if enable_parallel else 'Disabled'}")
        print(f"{'=' * 70}\n")

        # Create initial analysis record in database
        await db_service.create_analysis_record(
            analysis_id=analysis_id,
            filename=file.filename,
            analysis_type="parse_and_ai",
            model_name=model_name,
        )

        # Create folder structure (for backward compatibility/backup)
        structure = report_structure_service.create_analysis_structure(
            analysis_id, file.filename
        )

        # Save uploaded CAPE report temporarily
        with NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file_path = Path(temp_file.name)
            temp_files.append(temp_file_path)

        # Load and save CAPE data
        with open(temp_file_path, "r", encoding="utf-8") as f:
            cape_data = json.load(f)

        # Save to database
        await db_service.save_cape_results(analysis_id, cape_data)
        print("✅ CAPE report saved to database")

        # Also save to file system (optional backup)
        report_structure_service.save_cape_report(analysis_id, cape_data)

        # Parse the report
        print("\n🔧 STEP 1: Parsing CAPE Report...")
        print("-" * 70)
        parsed_results = parser_service.parse_complete_report(
            temp_file_path, structure["parsed"]
        )

        # Save to database
        await db_service.save_parsed_results(analysis_id, parsed_results)
        sections_parsed = parsed_results["metadata"]["sections_parsed"]
        print(f"✅ Parsed {len(sections_parsed)} sections saved to database")

        # Also save to file system (optional backup)
        report_structure_service.save_parsed_report(analysis_id, parsed_results)

        # AI Analysis
        print("\n🤖 STEP 2: AI Analysis...")
        print("-" * 70)
        ai_analysis_result = await ai_analysis_service.analyze(
            parsed_results=parsed_results,
            model_name=model_name,
            enable_parallel=enable_parallel,
            max_parallel_sections=max_parallel_sections,
        )

        malscore = parsed_results["sections"]["signatures"]["malscore"]

        # Save to database
        await db_service.save_ai_results(analysis_id, ai_analysis_result, malscore)
        ai_sections = ai_analysis_result.get("sections_analyzed", [])
        print(f"✅ AI analysis of {len(ai_sections)} sections saved to database")

        report_structure_service.save_ai_analysis(analysis_id, ai_analysis_result)

        await db_service.update_analysis_status(
            analysis_id,
            "complete",
            malscore=malscore,
            sections_parsed=sections_parsed,
            ai_sections_analyzed=ai_sections,
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

        print(f"\n{'=' * 70}")
        print("🎉 Parse + AI analysis COMPLETE!")
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
            "message": "Parse+AI analysis completed and stored in database",
            "components": ["cape", "parsed", "ai_analysis"],
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
        print(f"\n❌ Parse + AI analysis failed: {str(e)}")
        await db_service.update_analysis_status(analysis_id, "failed", error=str(e))
        import traceback

        traceback.print_exc()
        raise HTTPException(500, f"Parse + AI analysis failed: {str(e)}") from e
    finally:
        for temp_file in temp_files:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception:
                pass
