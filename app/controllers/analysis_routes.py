import json
import uuid
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.services.ai_analysis_service import AIAnalysisService
from app.services.cape_analysis_service import CapeAnalysisService
from app.services.chunking_service import ChunkingService
from app.services.model_service import ModelService
from app.services.parser_service import ParserService

router = APIRouter(
    prefix="/analysis",
    tags=["analysis"],
    responses={404: {"description": "Not found"}},
)


async def get_database_dep(db: AsyncIOMotorDatabase = Depends(get_database)):
    """Get database connection."""
    return db


async def get_analysis_service(db: AsyncIOMotorDatabase = Depends(get_database_dep)):
    """Get CAPE analysis service."""
    return CapeAnalysisService(db)


async def get_model_service():
    """Get AI model service with parallel support."""
    return ModelService()


async def get_parser_service():
    """Get CAPE report parser service."""
    return ParserService(models_dir=Path("app/parser"))


async def get_chunking_service():
    """Get chunking service for large sections."""
    return ChunkingService()


async def get_ai_analysis_service(
    model_service: ModelService = Depends(get_model_service),
    parser_service: ParserService = Depends(get_parser_service),
    chunking_service: ChunkingService = Depends(get_chunking_service),
):
    """Get AI analysis service with parallel processing."""
    return AIAnalysisService(model_service, parser_service, chunking_service)


@router.post("/", status_code=status.HTTP_201_CREATED)
async def complete_malware_analysis(
    file: UploadFile = File(...),
    model_name: Optional[str] = "gemini-2.5-flash",
    enable_parallel: bool = True,
    max_parallel_sections: int = 4,
    analysis_service: CapeAnalysisService = Depends(get_analysis_service),
    parser_service: ParserService = Depends(get_parser_service),
    ai_analysis_service: AIAnalysisService = Depends(get_ai_analysis_service),
    db: AsyncIOMotorDatabase = Depends(get_database_dep),
):
    """
    Complete malware analysis pipeline with parallel AI processing.

    Workflow:
    1. Submit file to CAPEv2 sandbox for dynamic analysis
    2. Parse CAPE report into structured sections
    3. Perform parallel AI analysis on all sections
    4. Store results in MongoDB
    5. Return comprehensive analysis results

    Args:
        file: Malware file to analyze
        model_name: AI model to use (default: gemini-2.5-flash)
        enable_parallel: Enable parallel section processing (default: True)
        max_parallel_sections: Max sections to process simultaneously (default: 4)

    Returns:
        Complete analysis results including CAPE, parsed sections, and AI analysis
    """
    analysis_id = str(uuid.uuid4())
    temp_files = []

    try:
        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="No filename provided"
            )

        supported_extensions = [
            ".exe",
            ".dll",
            ".pdf",
            ".doc",
            ".docx",
            ".js",
            ".vbs",
            ".zip",
            ".rar",
        ]

        if not any(file.filename.lower().endswith(ext) for ext in supported_extensions):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file type. Supported: {', '.join(supported_extensions)}",
            )

        print(f"\n{'=' * 70}")
        print("Starting Complete Malware Analysis")
        print(f"{'=' * 70}")
        print(f"File: {file.filename}")
        print(f"Analysis ID: {analysis_id}")
        print(f"AI Model: {model_name}")
        print(f"Parallel Mode: {'Enabled' if enable_parallel else 'Disabled'}")
        if enable_parallel:
            print(f"Max Parallel Sections: {max_parallel_sections}")
        print(f"{'=' * 70}\n")

        print("STEP 1: Submitting to CAPEv2 Sandbox...")
        print("-" * 70)
        cape_report = await analysis_service.upload_and_analyze(file)

        if not cape_report:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="CAPEv2 analysis failed - no report returned",
            )

        cape_task_id = cape_report.get("task_id", "N/A")
        print("CAPEv2 analysis completed")
        print(f"Task ID: {cape_task_id}")
        print(f"Report size: {len(str(cape_report))} characters\n")

        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            json.dump(cape_report, temp_file, indent=2)
            temp_report_path = Path(temp_file.name)
            temp_files.append(temp_report_path)

        print("STEP 2: Parsing CAPE Report...")
        print("-" * 70)
        output_dir = Path("temp_analysis_output") / analysis_id
        parsed_results = parser_service.parse_complete_report(
            temp_report_path, output_dir / "parsed"
        )
        sections_parsed = parsed_results["metadata"]["sections_parsed"]
        print("Report parsing completed")
        print(f"Sections parsed: {len(sections_parsed)}")
        print(f"Sections: {', '.join(sections_parsed)}")
        print(f"Output: {output_dir / 'parsed'}\n")

        print("STEP 3: AI Analysis Pipeline...")
        print("-" * 70)
        ai_analysis_result = await ai_analysis_service.analyze(
            parsed_results=parsed_results,
            model_name=model_name,
            enable_parallel=enable_parallel,
            max_parallel_sections=max_parallel_sections,
        )

        print("\nAI analysis completed")
        print(f"Analysis ID: {ai_analysis_result['analysis_id']}")
        print(f"Duration: {ai_analysis_result.get('duration_seconds', 0):.2f}s")
        print(f"Sections analyzed: {len(ai_analysis_result['sections_analyzed'])}")
        print(f"Model usage: {ai_analysis_result.get('model_usage', {})}")

        if "api_key_stats" in ai_analysis_result:
            stats = ai_analysis_result["api_key_stats"]
            if "gemini" in stats:
                print(f"API keys used: {stats['gemini']['total_keys']}")
                total_requests = sum(
                    s["requests"] for s in stats["gemini"]["key_stats"].values()
                )
                print(f"Total API requests: {total_requests}")
        print()

        print("STEP 4: Storing Results in Database...")
        print("-" * 70)
        final_result = {
            "analysis_id": analysis_id,
            "filename": file.filename,
            "timestamp": parsed_results["metadata"]["parsed_timestamp"],
            "cape_analysis": {
                "task_id": cape_task_id,
                "report_keys": list(cape_report.keys()) if cape_report else [],
                "report": cape_report,
            },
            "parsed_sections": {
                "sections": sections_parsed,
                "metadata": parsed_results["metadata"],
            },
            "ai_analysis": {
                "analysis_id": ai_analysis_result["analysis_id"],
                "sections_analyzed": ai_analysis_result["sections_analyzed"],
                "duration_seconds": ai_analysis_result.get("duration_seconds", 0),
                "model_usage": ai_analysis_result.get("model_usage", {}),
                "api_key_stats": ai_analysis_result.get("api_key_stats", {}),
                "chunking_summary": ai_analysis_result.get("chunking_summary", {}),
                "parallel_mode": enable_parallel,
                "results": ai_analysis_result["results"],
            },
            "output_directory": str(output_dir),
        }

        insert_result = await db["analyses"].insert_one(final_result)
        print("Stored in database")
        print(f"Database ID: {insert_result.inserted_id}\n")

        print(f"{'=' * 70}")
        print("Analysis Pipeline Completed Successfully")
        print(f"{'=' * 70}\n")

        response = {
            "status": "success",
            "analysis_id": analysis_id,
            "database_id": str(insert_result.inserted_id),
            "filename": file.filename,
            "timestamp": parsed_results["metadata"]["parsed_timestamp"],
            "cape_analysis": {
                "task_id": cape_task_id,
                "status": "completed",
                "report_sections": list(cape_report.keys()) if cape_report else [],
            },
            "parsing": {
                "sections_parsed": sections_parsed,
                "total_sections": len(sections_parsed),
            },
            "ai_analysis": {
                "analysis_id": ai_analysis_result["analysis_id"],
                "sections_analyzed": ai_analysis_result["sections_analyzed"],
                "total_sections": len(ai_analysis_result["sections_analyzed"]),
                "duration_seconds": ai_analysis_result.get("duration_seconds", 0),
                "parallel_mode": enable_parallel,
                "model_usage": ai_analysis_result.get("model_usage", {}),
                "final_synthesis_available": "final_synthesis"
                in ai_analysis_result["results"],
            },
            "performance": {
                "parallel_processing": enable_parallel,
                "max_parallel_sections": max_parallel_sections
                if enable_parallel
                else 1,
                "api_key_stats": ai_analysis_result.get("api_key_stats", {}),
            },
            "output": {
                "directory": str(output_dir),
                "parsed_reports": str(output_dir / "parsed"),
            },
        }

        return response

    except HTTPException:
        raise
    except Exception as e:
        print(f"\nAnalysis Failed: {str(e)}\n")
        import traceback

        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline failed: {str(e)}",
        ) from e
    finally:
        for temp_file in temp_files:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception as e:
                print(f"Could not delete temp file {temp_file}: {e}")


@router.post("/parse-existing", status_code=status.HTTP_201_CREATED)
async def analyze_existing_cape_report(
    file: UploadFile = File(...),
    model_name: Optional[str] = "gemini-2.5-flash",
    enable_parallel: bool = True,
    max_parallel_sections: int = 4,
    parser_service: ParserService = Depends(get_parser_service),
    ai_analysis_service: AIAnalysisService = Depends(get_ai_analysis_service),
    db: AsyncIOMotorDatabase = Depends(get_database_dep),
):
    """
    Parse existing CAPE report and perform AI analysis.

    Use this endpoint when you already have a CAPE JSON report
    and want to skip the sandbox analysis step.

    Args:
        file: CAPE report JSON file
        model_name: AI model to use
        enable_parallel: Enable parallel processing
        max_parallel_sections: Max parallel sections

    Returns:
        Complete analysis results (parsing + AI)
    """
    analysis_id = str(uuid.uuid4())
    temp_files = []

    try:
        if not file.filename or not file.filename.lower().endswith(".json"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only JSON files are supported",
            )

        print(f"\n{'=' * 70}")
        print("Analyzing Existing CAPE Report")
        print(f"{'=' * 70}")
        print(f"File: {file.filename}")
        print(f"Analysis ID: {analysis_id}")
        print(f"Parallel Mode: {'Enabled' if enable_parallel else 'Disabled'}")
        print(f"{'=' * 70}\n")

        with NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_path = Path(temp_file.name)
            temp_files.append(temp_path)

        print("STEP 1: Parsing CAPE Report...")
        print("-" * 70)
        output_dir = Path("temp_analysis_output") / analysis_id
        parsed_results = parser_service.parse_complete_report(
            temp_path, output_dir / "parsed"
        )
        sections_parsed = parsed_results["metadata"]["sections_parsed"]
        print("Parsing completed")
        print(f"Sections: {len(sections_parsed)} - {', '.join(sections_parsed)}\n")

        # STEP 2: AI Analysis
        print("STEP 2: AI Analysis Pipeline...")
        print("-" * 70)
        ai_analysis_result = await ai_analysis_service.analyze(
            parsed_results=parsed_results,
            model_name=model_name,
            enable_parallel=enable_parallel,
            max_parallel_sections=max_parallel_sections,
        )

        print("\nAI analysis completed")
        print(f"Duration: {ai_analysis_result.get('duration_seconds', 0):.2f}s\n")

        print("STEP 3: Storing in Database...")
        print("-" * 70)
        final_result = {
            "analysis_id": analysis_id,
            "filename": file.filename,
            "source": "existing_report",
            "timestamp": parsed_results["metadata"]["parsed_timestamp"],
            "parsed_sections": {
                "sections": sections_parsed,
                "metadata": parsed_results["metadata"],
            },
            "ai_analysis": {
                "analysis_id": ai_analysis_result["analysis_id"],
                "sections_analyzed": ai_analysis_result["sections_analyzed"],
                "duration_seconds": ai_analysis_result.get("duration_seconds", 0),
                "model_usage": ai_analysis_result.get("model_usage", {}),
                "api_key_stats": ai_analysis_result.get("api_key_stats", {}),
                "parallel_mode": enable_parallel,
                "results": ai_analysis_result["results"],
            },
        }

        insert_result = await db["analyses"].insert_one(final_result)
        print("Stored successfully\n")
        print(f"{'=' * 70}")
        print("Analysis Completed")
        print(f"{'=' * 70}\n")

        return {
            "status": "success",
            "analysis_id": analysis_id,
            "database_id": str(insert_result.inserted_id),
            "original_file": file.filename,
            "parsing": {
                "sections_parsed": sections_parsed,
                "total_sections": len(sections_parsed),
            },
            "ai_analysis": {
                "sections_analyzed": ai_analysis_result["sections_analyzed"],
                "duration_seconds": ai_analysis_result.get("duration_seconds", 0),
                "parallel_mode": enable_parallel,
                "model_usage": ai_analysis_result.get("model_usage", {}),
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"\nAnalysis Failed: {str(e)}\n")
        import traceback

        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}",
        ) from e
    finally:
        for temp_file in temp_files:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception:
                pass


@router.get("/{analysis_id}")
async def get_analysis_results(
    analysis_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database_dep),
):
    """
    Retrieve complete analysis results by ID.

    Args:
        analysis_id: Analysis ID returned from analysis endpoint

    Returns:
        Complete analysis results including all sections
    """
    try:
        result = await db["analyses"].find_one({"analysis_id": analysis_id})

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis {analysis_id} not found",
            )

        result.pop("_id", None)

        return {"status": "success", "data": result}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve analysis: {str(e)}",
        ) from e
