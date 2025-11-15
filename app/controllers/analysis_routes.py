import json
import uuid
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.services.analysis_service import AnalysisService
from app.services.model_service import ModelService
from app.services.parser_service import ParserService

router = APIRouter(
    prefix="/analysis",
    tags=["analysis"],
    responses={404: {"description": "Not found"}},
)


async def get_analysis_service(db: AsyncIOMotorDatabase = Depends(get_database)):
    return AnalysisService(db)


async def get_model_service():
    return ModelService()


async def get_parser_service():
    return ParserService(models_dir=Path("app/parser"))


@router.post("/", status_code=status.HTTP_201_CREATED)
async def upload_and_analyze_file(
    file: UploadFile = File(...),
    model_name: Optional[str] = None,
    analysis_service: AnalysisService = Depends(get_analysis_service),
    model_service: ModelService = Depends(get_model_service),
    parser_service: ParserService = Depends(get_parser_service),
):
    """
    Upload a malware file to CAPEv2 server for analysis, parse the result,
    and process with AI model.
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

        print(f"Starting analysis {analysis_id} for file: {file.filename}")

        print("STEP 1: Submitting file to CAPEv2...")
        cape_report = await analysis_service.upload_and_analyze(file)

        if not cape_report:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to analyze file with CAPEv2",
            )

        print(
            f"✓ CAPE analysis completed, task ID: {cape_report.get('task_id', 'N/A')}"
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
                f"✓ Report parsed successfully. Sections: {len(parsed_results['metadata']['sections_parsed'])}"
            )

            # --- STEP 3: Process with AI model ---
            print("STEP 3: Processing with AI model...")

            # Prepare prompt for AI analysis
            analysis_prompt = f"""
            Analyze this malware analysis report and provide a comprehensive assessment:

            File: {file.filename}
            Analysis ID: {analysis_id}

            Key Findings:

            Please provide:
            1. Overall threat assessment
            2. Key indicators of compromise (IOCs)
            3. Behavioral analysis summary
            4. Recommended actions
            5. Confidence level in assessment
            """

            # Use AI model to analyze the parsed results
            ai_analysis = await model_service.process_request(
                prompt=analysis_prompt, model_name=model_name
            )

            print("✓ AI analysis completed")

            # --- STEP 4: Store results in database ---
            final_result = {
                "analysis_id": analysis_id,
                "filename": file.filename,
                "cape_report": cape_report,
                "parsed_results": parsed_results,
                "ai_analysis": ai_analysis,
                "timestamp": parsed_results["metadata"]["parsed_timestamp"],
            }

            # Store in MongoDB
            await analysis_service.collection.insert_one(final_result)

            return {
                "analysis_id": analysis_id,
                "filename": file.filename,
                "status": "completed",
                "sections_parsed": parsed_results["metadata"]["sections_parsed"],
                "ai_model_used": ai_analysis.get("model", model_name),
                # "summary": self._create_summary_response(parsed_results, ai_analysis),
            }

        finally:
            # Clean up temporary file
            temp_report_path.unlink(missing_ok=True)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}",
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


@router.post("/ai-only")
async def ai_analysis_only(
    prompt: str,
    model_name: Optional[str] = None,
    file: UploadFile = File(None),
    model_service: ModelService = Depends(get_model_service),
):
    """
    Only use AI model for analysis. Can optionally include a file for context.
    Useful for testing AI model integration.
    """
    try:
        file_content = None
        filename = None

        if file:
            file_content = await file.read()
            filename = file.filename

        result = await model_service.process_request(
            prompt=prompt,
            file_content=file_content,
            filename=filename,
            model_name=model_name,
        )

        return {
            "status": "success",
            "model_used": result.get("model"),
            "response": result.get("response"),
            "usage": result.get("usage", {}),
            "prompt_length": len(prompt),
            "file_included": file is not None,
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI analysis failed: {str(e)}",
        ) from e
