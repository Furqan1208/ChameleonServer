from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.services.report_structure_service import report_structure_service

from .dependencies import get_database_dep

router = APIRouter()


@router.get("/reports")
async def get_all_reports():
    """
    Get all analysis reports.
    """
    try:
        analyses = report_structure_service.get_all_analyses()
        return {"status": "success", "data": analyses, "count": len(analyses)}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get reports: {str(e)}",
        ) from e


@router.get("/{analysis_id}")
async def get_analysis_results(
    analysis_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database_dep),
):
    """
    Retrieve complete analysis results by ID.
    """
    try:
        analysis = report_structure_service.get_analysis(analysis_id)

        if not analysis:
            db_result = await db["analyses"].find_one({"analysis_id": analysis_id})

            if not db_result:
                raise HTTPException(404, f"Analysis {analysis_id} not found")

            db_result.pop("_id", None)
            return {"status": "success", "data": db_result}

        return {"status": "success", "data": analysis}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to retrieve analysis: {str(e)}") from e


@router.get("/{analysis_id}/components")
async def get_analysis_components(analysis_id: str):
    """
    Get available components for an analysis
    """
    analysis = report_structure_service.get_analysis(analysis_id)

    if not analysis:
        raise HTTPException(404, f"Analysis {analysis_id} not found")

    components = analysis["metadata"].get("components", {})

    return {
        "analysis_id": analysis_id,
        "status": "success",
        "components": components,
        "available": [k for k, v in components.items() if v],
    }


@router.get("/{analysis_id}/cape")
async def get_cape_report(analysis_id: str):
    """
    Get CAPE raw report
    """
    analysis = report_structure_service.get_analysis(analysis_id)

    if not analysis or "cape" not in analysis:
        raise HTTPException(404, f"CAPE report not found for {analysis_id}")

    return {"analysis_id": analysis_id, "type": "cape_raw", "data": analysis["cape"]}


@router.get("/{analysis_id}/parsed/{section_name}")
async def get_parsed_section(analysis_id: str, section_name: str = "all"):
    """
    Get specific parsed section or all sections
    """
    analysis = report_structure_service.get_analysis(analysis_id)

    if not analysis or "parsed" not in analysis:
        raise HTTPException(404, f"Parsed data not found for {analysis_id}")

    if section_name == "all":
        return {
            "analysis_id": analysis_id,
            "type": "parsed_all",
            "data": analysis["parsed"],
        }
    else:
        sections = analysis["parsed"].get("sections", {})
        if section_name not in sections:
            raise HTTPException(404, f"Section {section_name} not found")

        return {
            "analysis_id": analysis_id,
            "type": "parsed_section",
            "section": section_name,
            "data": sections[section_name],
        }


@router.get("/{analysis_id}/ai/{section_name}")
async def get_ai_section(analysis_id: str, section_name: str = "summary"):
    """
    Get specific AI analysis section or summary.
    When section_name='summary', combines all AI analysis files into a single response.
    """
    try:
        analysis = report_structure_service.get_analysis(analysis_id)

        if not analysis or "ai_analysis" not in analysis:
            raise HTTPException(404, f"AI analysis not found for {analysis_id}")

        if section_name == "summary":
            summary_file = (
                report_structure_service.base_dir
                / analysis_id
                / "ai_analysis"
                / "summary.json"
            )
            if not summary_file.exists():
                raise HTTPException(404, f"AI summary not found for {analysis_id}")

            summary_data = report_structure_service.load_json(summary_file)

            model_usage_file = (
                report_structure_service.base_dir
                / analysis_id
                / "ai_analysis"
                / "model_usage.json"
            )
            model_usage_data = {}
            if model_usage_file.exists():
                model_usage_data = report_structure_service.load_json(model_usage_file)

            ai_dir = (
                report_structure_service.base_dir
                / analysis_id
                / "ai_analysis"
                / "sections"
            )
            sections_data = {}
            sections_analyzed = []

            if ai_dir.exists() and ai_dir.is_dir():
                for section_file in ai_dir.glob("*.json"):
                    section_name_key = section_file.stem
                    section_data = report_structure_service.load_json(section_file)
                    sections_data[section_name_key] = section_data
                    sections_analyzed.append(section_name_key)

            combined_data = {
                **summary_data,
                "model_usage": model_usage_data,
                "sections": sections_data,
                "sections_analyzed": sections_analyzed,
                "results": {},
                "duration_seconds": summary_data.get("duration_seconds", 0),
                "timestamp": summary_data.get("timestamp", datetime.now().isoformat()),
            }

            for section_name_key, section_data in sections_data.items():
                if "analysis" in section_data:
                    if section_name_key == "final_synthesis":
                        combined_data["results"]["final_synthesis"] = section_data[
                            "analysis"
                        ]
                    else:
                        combined_data["results"][section_name_key] = section_data[
                            "analysis"
                        ]

            if (
                "final_synthesis" not in combined_data["results"]
                and "final_synthesis" in sections_data
            ):
                if "analysis" in sections_data["final_synthesis"]:
                    combined_data["results"]["final_synthesis"] = sections_data[
                        "final_synthesis"
                    ]["analysis"]

            for section_name_key, section_data in sections_data.items():
                if "analysis" in section_data:
                    combined_data[section_name_key] = section_data["analysis"]

            return {
                "analysis_id": analysis_id,
                "type": "ai_summary",
                "data": combined_data,
            }
        else:
            ai_dir = (
                report_structure_service.base_dir
                / analysis_id
                / "ai_analysis"
                / "sections"
            )
            section_file = ai_dir / f"{section_name}.json"

            if not section_file.exists():
                raise HTTPException(404, f"AI section {section_name} not found")

            data = report_structure_service.load_json(section_file)

            return {
                "analysis_id": analysis_id,
                "type": "ai_section",
                "section": section_name,
                "data": data,
            }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error loading AI section {section_name} for {analysis_id}: {str(e)}")
        raise HTTPException(500, f"Failed to load AI analysis: {str(e)}") from e


@router.delete("/{analysis_id}")
async def delete_analysis(analysis_id: str):
    """
    Delete an analysis.
    """
    try:
        deleted = report_structure_service.delete_analysis(analysis_id)

        if not deleted:
            raise HTTPException(404, f"Analysis {analysis_id} not found")

        return {
            "status": "success",
            "message": f"Analysis {analysis_id} deleted successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to delete analysis: {str(e)}") from e


@router.get("/{analysis_id}/download")
async def download_report(analysis_id: str, format: str = "json"):
    """
    Download analysis report.
    """
    try:
        analysis = report_structure_service.get_analysis(analysis_id)

        if not analysis:
            raise HTTPException(404, f"Analysis {analysis_id} not found")

        if format.lower() == "json":
            return analysis

        raise HTTPException(501, f"Format {format} not yet supported")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to download report: {str(e)}") from e
