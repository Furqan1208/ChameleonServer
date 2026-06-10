# D:\FYP\ChameleonServer\app\controllers\analysis_routes\reports.py
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.concurrency import run_in_threadpool
from bson import ObjectId
import json
from datetime import datetime
from typing import Any, Dict, List

from app.ml.ml_prediction_service import MLPredictionService

from app.services.database_service import DatabaseService
from app.services.pdf_report_service import PDFReportService

from .dependencies import get_current_user_id, get_db_service, get_pdf_report_service

router = APIRouter()


def convert_objectid_to_str(obj: Any) -> Any:
    """
    Recursively convert ObjectId instances to strings for JSON serialization.
    Also handles datetime objects and other non-serializable types.
    """
    if isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {key: convert_objectid_to_str(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_objectid_to_str(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_objectid_to_str(item) for item in obj)
    else:
        return obj


@router.get("/reports")
async def get_all_reports(
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    user_id: str = Depends(get_current_user_id),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Get all analysis reports for the current user with pagination.
    """
    try:
        analyses = await db_service.get_all_analyses(
            user_id=user_id, limit=limit, skip=skip
        )
        total = await db_service.get_analysis_count(user_id=user_id)

        # Convert ObjectId to string for JSON serialization
        analyses = convert_objectid_to_str(analyses)

        return {
            "status": "success",
            "data": analyses,
            "count": len(analyses),
            "total": total,
            "limit": limit,
            "skip": skip,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get reports: {str(e)}",
        ) from e


@router.get("/{analysis_id}")
async def get_analysis_results(
    analysis_id: str,
    include_details: bool = Query(
        False, description="Include CAPE, parsed, and AI results"
    ),
    user_id: str = Depends(get_current_user_id),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Retrieve analysis results by ID, scoped to current user.
    Set include_details=true to get all components (CAPE, parsed, AI results).
    """
    try:
        # ADDED_ML: Optional ML prediction added as non-breaking extra field.
        ml_prediction = None
        try:
            predictor = MLPredictionService.get_instance()
            ml_prediction = await predictor.predict_from_analysis_id(
                analysis_id=analysis_id,
                db=db_service.db,
                user_id=user_id,
            )
            if not ml_prediction.get("ml_available", False):
                ml_prediction = None
        except Exception:
            ml_prediction = None

        if include_details:
            result = await db_service.get_complete_analysis(
                user_id=user_id, analysis_id=analysis_id
            )
            if not result:
                raise HTTPException(404, f"Analysis {analysis_id} not found")
            result["ml"] = ml_prediction
            
            # Convert ObjectId to string for JSON serialization
            result = convert_objectid_to_str(result)
            
            return {"status": "success", "data": result}
        else:
            analysis = await db_service.get_analysis(
                user_id=user_id, analysis_id=analysis_id
            )
            if not analysis:
                raise HTTPException(404, f"Analysis {analysis_id} not found")
            analysis["ml"] = ml_prediction
            
            # Convert ObjectId to string for JSON serialization
            analysis = convert_objectid_to_str(analysis)
            
            return {"status": "success", "data": analysis}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to retrieve analysis: {str(e)}") from e


@router.get("/{analysis_id}/components")
async def get_analysis_components(
    analysis_id: str,
    user_id: str = Depends(get_current_user_id),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Get available components for an analysis, scoped to current user.
    """
    analysis = await db_service.get_analysis(user_id=user_id, analysis_id=analysis_id)

    if not analysis:
        raise HTTPException(404, f"Analysis {analysis_id} not found")

    components = analysis.get("components", {})

    return {
        "analysis_id": analysis_id,
        "status": "success",
        "components": components,
        "available": [k for k, v in components.items() if v],
    }


@router.get("/{analysis_id}/cape")
async def get_cape_report(
    analysis_id: str,
    user_id: str = Depends(get_current_user_id),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Get CAPE raw report, scoped to current user.
    Reads from file system (MongoDB stores only metadata).
    """
    # Verify ownership first
    cape_result = await db_service.get_cape_results(
        user_id=user_id, analysis_id=analysis_id
    )

    if not cape_result:
        raise HTTPException(404, f"CAPE report not found for {analysis_id}")

    # Read full report from file system
    from app.services.report_structure_service import report_structure_service
    from pathlib import Path
    
    analysis_dir = report_structure_service.base_dir / analysis_id
    cape_file = analysis_dir / "cape" / "raw_report.json"
    
    if not cape_file.exists():
        raise HTTPException(500, f"CAPE report file not found at {cape_file}")
    
    try:
        cape_data = report_structure_service.load_json(cape_file)
    except Exception as e:
        raise HTTPException(500, f"Failed to load CAPE report: {str(e)}")

    return {
        "analysis_id": analysis_id,
        "type": "cape_raw",
        "data": cape_data,
        "created_at": cape_result.get("created_at"),
    }


@router.get("/{analysis_id}/parsed")
async def get_parsed_results(
    analysis_id: str,
    section: str = Query(None, description="Specific section name, or None for all"),
    user_id: str = Depends(get_current_user_id),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Get parsed results, scoped to current user.
    Optionally specify a section name to get only that section.
    """
    parsed_result = await db_service.get_parsed_results(
        user_id=user_id, analysis_id=analysis_id
    )

    if not parsed_result:
        raise HTTPException(404, f"Parsed data not found for {analysis_id}")

    if section:
        sections = parsed_result.get("sections", {})
        if section not in sections:
            raise HTTPException(404, f"Section {section} not found")
        return {
            "analysis_id": analysis_id,
            "type": "parsed_section",
            "section": section,
            "data": sections[section],
        }

    return {
        "analysis_id": analysis_id,
        "type": "parsed_all",
        "data": parsed_result,
    }


@router.get("/{analysis_id}/ai")
async def get_ai_results(
    analysis_id: str,
    section: str = Query(None, description="Specific section name, or None for all"),
    user_id: str = Depends(get_current_user_id),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Get AI analysis results, scoped to current user.
    Optionally specify a section name to get only that section.
    """
    ai_result = await db_service.get_ai_results(
        user_id=user_id, analysis_id=analysis_id
    )

    if not ai_result:
        raise HTTPException(404, f"AI analysis not found for {analysis_id}")

    if section:
        results = ai_result.get("results", {})
        if section not in results:
            raise HTTPException(404, f"AI section {section} not found")
        return {
            "analysis_id": analysis_id,
            "type": "ai_section",
            "section": section,
            "data": results[section],
            "created_at": ai_result.get("created_at"),
        }

    return {
        "analysis_id": analysis_id,
        "type": "ai_all",
        "data": {
            "results": ai_result.get("results", {}),
            "sections_analyzed": ai_result.get("sections_analyzed", []),
            "model_usage": ai_result.get("model_usage", {}),
            "duration_seconds": ai_result.get("duration_seconds", 0),
            "timestamp": ai_result.get("timestamp"),
        },
        "created_at": ai_result.get("created_at"),
    }


@router.delete("/{analysis_id}")
async def delete_analysis(
    analysis_id: str,
    user_id: str = Depends(get_current_user_id),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Delete an analysis and all related data, scoped to current user.
    """
    try:
        deleted = await db_service.delete_analysis(
            user_id=user_id, analysis_id=analysis_id
        )

        if not deleted:
            raise HTTPException(404, f"Analysis {analysis_id} not found")

        return {
            "status": "success",
            "message": f"Analysis {analysis_id} and related data deleted successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to delete analysis: {str(e)}") from e


@router.get("/{analysis_id}/download")
async def download_report(
    analysis_id: str,
    format: str = Query("json", regex="^(json)$"),
    include_all: bool = Query(True, description="Include all components"),
    user_id: str = Depends(get_current_user_id),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Download complete analysis report as JSON, scoped to current user.
    """
    try:
        if include_all:
            result = await db_service.get_complete_analysis(
                user_id=user_id, analysis_id=analysis_id
            )
        else:
            analysis = await db_service.get_analysis(
                user_id=user_id, analysis_id=analysis_id
            )
            result = {"analysis": analysis}

        if not result:
            raise HTTPException(404, f"Analysis {analysis_id} not found")

        # Convert ObjectId to string for JSON serialization
        result = convert_objectid_to_str(result)

        if format.lower() == "json":
            return result

        raise HTTPException(501, f"Format {format} not yet supported")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to download report: {str(e)}") from e


@router.get("/{analysis_id}/download/pdf")
async def download_pdf_report(
    analysis_id: str,
    user_id: str = Depends(get_current_user_id),
    db_service: DatabaseService = Depends(get_db_service),
    pdf_report_service: PDFReportService = Depends(get_pdf_report_service),
):
    """
    Download CAPE + AI analysis report as PDF.
    """
    try:
        # Get complete analysis data
        result = await db_service.get_complete_analysis(
            user_id=user_id, analysis_id=analysis_id
        )
        
        if not result:
            raise HTTPException(404, f"Analysis {analysis_id} not found")
        
        # Convert ObjectId to string
        result = convert_objectid_to_str(result)
        
        pdf_bytes = await run_in_threadpool(
            pdf_report_service.generate_pdf_report,
            result  # Pass the entire result directly
        )

        analysis = result.get("analysis", {})
        safe_filename = str(analysis.get("filename", "analysis_report")).replace('"', "")
        content_disposition = (
            f'attachment; filename="{analysis_id}_{safe_filename}_report.pdf"'
        )

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": content_disposition},
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to generate PDF report: {str(e)}") from e