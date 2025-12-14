from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.services.database_service import DatabaseService

from .dependencies import get_db_service

router = APIRouter()


@router.get("/reports")
async def get_all_reports(
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Get all analysis reports from database with pagination.
    """
    try:
        analyses = await db_service.get_all_analyses(limit=limit, skip=skip)
        total = await db_service.get_analysis_count()

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
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Retrieve analysis results by ID.
    Set include_details=true to get all components (CAPE, parsed, AI results).
    """
    try:
        if include_details:
            # Get complete analysis with all components
            result = await db_service.get_complete_analysis(analysis_id)

            if not result:
                raise HTTPException(404, f"Analysis {analysis_id} not found")

            return {"status": "success", "data": result}
        else:
            # Get only analysis metadata
            analysis = await db_service.get_analysis(analysis_id)

            if not analysis:
                raise HTTPException(404, f"Analysis {analysis_id} not found")

            return {"status": "success", "data": analysis}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to retrieve analysis: {str(e)}") from e


@router.get("/{analysis_id}/components")
async def get_analysis_components(
    analysis_id: str,
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Get available components for an analysis
    """
    analysis = await db_service.get_analysis(analysis_id)

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
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Get CAPE raw report from database
    """
    cape_result = await db_service.get_cape_results(analysis_id)

    if not cape_result:
        raise HTTPException(404, f"CAPE report not found for {analysis_id}")

    return {
        "analysis_id": analysis_id,
        "type": "cape_raw",
        "data": cape_result.get("data", {}),
        "created_at": cape_result.get("created_at"),
    }


@router.get("/{analysis_id}/parsed")
async def get_parsed_results(
    analysis_id: str,
    section: str = Query(None, description="Specific section name, or None for all"),
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Get parsed results from database.
    Optionally specify a section name to get only that section.
    """
    parsed_result = await db_service.get_parsed_results(analysis_id)

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
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Get AI analysis results from database.
    Optionally specify a section name to get only that section.
    """
    ai_result = await db_service.get_ai_results(analysis_id)

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
    else:
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
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Delete an analysis and all related data from database.
    """
    try:
        deleted = await db_service.delete_analysis(analysis_id)

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
    db_service: DatabaseService = Depends(get_db_service),
):
    """
    Download complete analysis report from database.
    """
    try:
        if include_all:
            result = await db_service.get_complete_analysis(analysis_id)
        else:
            analysis = await db_service.get_analysis(analysis_id)
            result = {"analysis": analysis}

        if not result:
            raise HTTPException(404, f"Analysis {analysis_id} not found")

        if format.lower() == "json":
            return result

        raise HTTPException(501, f"Format {format} not yet supported")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to download report: {str(e)}") from e
