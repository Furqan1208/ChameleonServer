# D:\FYP\ChameleonServer\app\controllers\analysis_routes.py
import json
import uuid
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.services.analysis_service import AnalysisService
from app.services.enhanced_model_service import EnhancedModelService
from app.services.parser_service import ParserService
from app.services.chunking_service import ChunkingService
from app.services.enhanced_analysis_service import EnhancedAnalysisService
from app.services.robust_model_service import RobustModelService

router = APIRouter(
    prefix="/analysis",
    tags=["analysis"],
    responses={404: {"description": "Not found"}},
)


# Dependency injection functions
async def get_analysis_service(db: AsyncIOMotorDatabase = Depends(get_database)):
    return AnalysisService(db)


async def get_enhanced_model_service():
    return EnhancedModelService()


async def get_robust_model_service(
    enhanced_model_service: EnhancedModelService = Depends(get_enhanced_model_service)
):
    return RobustModelService(enhanced_model_service)


async def get_parser_service():
    return ParserService(models_dir=Path("app/parser"))


async def get_chunking_service():
    return ChunkingService()


async def get_enhanced_analysis_service(
    enhanced_model_service: EnhancedModelService = Depends(get_enhanced_model_service),
    parser_service: ParserService = Depends(get_parser_service),
    chunking_service: ChunkingService = Depends(get_chunking_service)
):
    return EnhancedAnalysisService(enhanced_model_service, parser_service, chunking_service)


@router.post("/", status_code=status.HTTP_201_CREATED)
async def upload_and_analyze_file(
    file: UploadFile = File(...),
    model_name: Optional[str] = None,
    analysis_service: AnalysisService = Depends(get_analysis_service),
    parser_service: ParserService = Depends(get_parser_service),
    enhanced_analysis_service: EnhancedAnalysisService = Depends(get_enhanced_analysis_service),
):
    """
    Upload a malware file to CAPEv2 server for analysis, parse the result,
    and process with AI model using enhanced progressive analysis with chunking.
    """
    try:
        if not file.filename or not any(
            file.filename.lower().endswith(ext)
            for ext in [".exe", ".dll", ".pdf", ".doc", ".docx", ".js", ".vbs"]
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported file type. Supported: exe, dll, pdf, doc, docx, js, vbs",
            )

        analysis_id = str(uuid.uuid4())

        print(f"🚀 Starting enhanced analysis {analysis_id} for file: {file.filename}")

        print("STEP 1: Submitting file to CAPEv2...")
        cape_report = await analysis_service.upload_and_analyze(file)

        if not cape_report:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to analyze file with CAPEv2",
            )

        print(
            f"✅ CAPE analysis completed, task ID: {cape_report.get('task_id', 'N/A')}"
        )

        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            json.dump(cape_report, temp_file, indent=2)
            temp_report_path = Path(temp_file.name)

        try:
            print("STEP 2: Parsing CAPE report...")
            parsed_results = parser_service.parse_complete_report(
                temp_report_path, Path("temp_analysis_output")
            )

            print(
                f"✅ Report parsed successfully. Sections: {len(parsed_results['metadata']['sections_parsed'])}"
            )

            # --- STEP 3: Enhanced Progressive AI Analysis with Chunking ---
            print("STEP 3: Starting enhanced progressive AI analysis with chunking...")
            
            # Use enhanced analysis service with chunking support
            analysis_result = await enhanced_analysis_service.progressive_analysis(
                parsed_results=parsed_results,
                model_name=model_name,
                output_dir=Path("temp_analysis_output") / analysis_id
            )

            print("✅ Enhanced progressive AI analysis completed")

            # --- STEP 4: Store results in database ---
            final_result = {
                "analysis_id": analysis_id,
                "filename": file.filename,
                "cape_report": cape_report,
                "parsed_results": parsed_results,
                "enhanced_ai_analysis": analysis_result,
                "timestamp": parsed_results["metadata"]["parsed_timestamp"],
            }

            # Store in MongoDB
            await analysis_service.collection.insert_one(final_result)

            return {
                "analysis_id": analysis_id,
                "filename": file.filename,
                "status": "completed",
                "sections_parsed": parsed_results["metadata"]["sections_parsed"],
                "ai_analyses_performed": analysis_result["sections_analyzed"],
                "chunking_analysis": analysis_result.get("chunking_analysis", {}),
                "model_usage": analysis_result.get("model_usage", {}),
                "output_directory": analysis_result["output_directory"],
                "final_report_available": "final_synthesis" in analysis_result["results"]
            }

        finally:
            # Clean up temporary file
            temp_report_path.unlink(missing_ok=True)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Enhanced analysis failed: {str(e)}",
        ) from e


@router.post("/parse-and-analyze")
async def parse_and_analyze_existing_report(
    file: UploadFile = File(...),
    model_name: Optional[str] = None,
    analysis_service: AnalysisService = Depends(get_analysis_service),
    parser_service: ParserService = Depends(get_parser_service),
    enhanced_analysis_service: EnhancedAnalysisService = Depends(get_enhanced_analysis_service)
):
    """
    Parse existing CAPE report and perform enhanced progressive AI analysis
    with chunking support. Perfect for testing without CAPE access.
    """
    try:
        if not file.filename or not file.filename.lower().endswith(".json"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only JSON files are supported"
            )

        # Save uploaded file temporarily
        with NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_path = Path(temp_file.name)

        print(f"📄 Processing CAPE report: {file.filename}")
        
        try:
            # Step 1: Parse the CAPE report
            print("🔧 Step 1: Parsing CAPE report...")
            parsed_results = parser_service.parse_complete_report(
                temp_path, 
                Path("temp_parse_output")
            )
            await analysis_service.collection.insert_one(parsed_results)
            
            
            print(f"✅ Parsing completed. Sections: {len(parsed_results['metadata']['sections_parsed'])}")

            # Step 2: Enhanced Progressive AI Analysis with chunking
            print("🤖 Step 2: Starting enhanced progressive AI analysis with chunking...")
            analysis_result = await enhanced_analysis_service.progressive_analysis(
                parsed_results=parsed_results,
                model_name=model_name
            )
            
            

            return {
                "status": "success",
                "analysis_id": analysis_result["analysis_id"],
                "original_file": file.filename,
                "parsed_sections": parsed_results["metadata"]["sections_parsed"],
                "ai_analyses_performed": analysis_result["sections_analyzed"],
                "chunking_analysis": analysis_result.get("chunking_analysis", {}),
                "model_usage": analysis_result.get("model_usage", {}),
                "output_directory": analysis_result["output_directory"],
                "final_report_available": "final_synthesis" in analysis_result["results"]
            }

        finally:
            # Clean up temporary file
            temp_path.unlink(missing_ok=True)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Parse and analyze failed: {str(e)}"
        ) from e


@router.post("/enhanced-ai-only")
async def enhanced_ai_analysis_only(
    prompt: str,
    model_name: Optional[str] = None,
    file: UploadFile = File(None),
    robust_model_service: RobustModelService = Depends(get_robust_model_service),
):
    """
    Use enhanced AI model service with robust fallback for analysis. 
    Can optionally include a file for context.
    """
    try:
        file_content = None
        filename = None

        if file:
            file_content = await file.read()
            filename = file.filename

        result = await robust_model_service.process_request_with_enhanced_fallback(
            prompt=prompt,
            file_content=file_content,
            filename=filename,
            preferred_model=model_name,
            analysis_id="direct_ai_request",
            section_name="direct_analysis"
        )

        return {
            "status": "success",
            "model_used": result.get("metadata", {}).get("model_used"),
            "reliability_score": result.get("metadata", {}).get("reliability_score"),
            "response_time": result.get("metadata", {}).get("response_time_seconds"),
            "quality_score": result.get("metadata", {}).get("quality_score"),
            "total_attempts": result.get("metadata", {}).get("total_attempts"),
            "response": result.get("response"),
            "prompt_length": len(prompt),
            "file_included": file is not None,
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Enhanced AI analysis failed: {str(e)}",
        ) from e


@router.get("/model-stats")
async def get_model_statistics(
    robust_model_service: RobustModelService = Depends(get_robust_model_service)
):
    """
    Get statistics about model performance and reliability.
    """
    try:
        stats = robust_model_service.get_model_stats()
        best_models = robust_model_service.get_best_models(5)
        
        return {
            "status": "success",
            "best_models": best_models,
            "model_reliability": stats["model_reliability"],
            "model_performance": stats["model_performance"],
            "failure_summary": stats["failure_tracker_summary"],
            "success_summary": stats["success_tracker_summary"]
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get model statistics: {str(e)}"
        ) from e


@router.post("/cape-only", status_code=status.HTTP_201_CREATED)
async def cape_analysis_only(
    file: UploadFile = File(...),
    analysis_service: AnalysisService = Depends(get_analysis_service),
):
    """
    Only perform CAPEv2 analysis without parsing or AI processing.
    Useful for testing CAPE integration.
    """
    try:
        print(f"CAPE-only analysis for: {file.filename}")

        cape_report = await analysis_service.upload_and_analyze(file)

        if not cape_report:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="CAPEv2 analysis failed",
            )

        return {
            "status": "success",
            "filename": file.filename,
            "report_keys": list(cape_report.keys()) if cape_report else [],
            "message": "CAPE analysis completed successfully",
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"CAPE analysis failed: {str(e)}",
        ) from e


@router.post("/parse-only")
async def parse_existing_report(
    file: UploadFile = File(...),
    parser_service: ParserService = Depends(get_parser_service),
):
    """
    Parse an existing CAPE JSON report file.
    Useful for testing the parser service.
    """
    try:
        if not file.filename or not file.filename.lower().endswith(".json"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only JSON files are supported",
            )

        # Save uploaded file temporarily
        with NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_path = Path(temp_file.name)

        print(f"Parsing report file: {temp_path}")
        try:
            # Parse the report
            parsed_results = parser_service.parse_complete_report(
                temp_path, Path("temp_parse_output")
            )

            return {
                "status": "success",
                "original_file": file.filename,
                "sections_parsed": parsed_results["metadata"]["sections_parsed"],
                "section_summary": get_section_summary(parsed_results),
                "output_location": "temp_parse_output",
            }

        finally:
            temp_path.unlink(missing_ok=True)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Parsing failed: {str(e)}",
        ) from e


@router.post("/chunking-analysis")
async def analyze_chunking_requirements(
    file: UploadFile = File(...),
    parser_service: ParserService = Depends(get_parser_service),
    chunking_service: ChunkingService = Depends(get_chunking_service)
):
    """
    Analyze a CAPE report to determine chunking requirements for large sections.
    """
    try:
        if not file.filename or not file.filename.lower().endswith(".json"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only JSON files are supported",
            )

        # Save uploaded file temporarily
        with NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_path = Path(temp_file.name)

        try:
            # Parse the report
            parsed_results = parser_service.parse_complete_report(
                temp_path, Path("temp_parse_output")
            )

            # Analyze chunking requirements
            chunking_analysis = chunking_service.analyze_chunking_requirements(parsed_results)

            return {
                "status": "success",
                "original_file": file.filename,
                "chunking_analysis": chunking_analysis,
                "sections_parsed": parsed_results["metadata"]["sections_parsed"],
            }

        finally:
            temp_path.unlink(missing_ok=True)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Chunking analysis failed: {str(e)}",
        ) from e


def get_section_summary(parsed_results):
    """
    Helper function to summarize parsed report sections.
    """
    metadata = parsed_results.get("metadata", {})
    sections = metadata.get("sections_parsed", [])
    return {
        "total_sections": len(sections),
        "sections": sections,
        "parsed_timestamp": metadata.get("parsed_timestamp"),
    }