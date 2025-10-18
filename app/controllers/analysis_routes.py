from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.services.analysis_service import AnalysisService
from app.services.model_service import ModelService

router = APIRouter(
    prefix="/analysis",
    tags=["analysis"],
    responses={404: {"description": "Not found"}},
)


async def get_analysis_service(db: AsyncIOMotorDatabase = Depends(get_database)):
    return AnalysisService(db)


async def get_model_service():
    return ModelService()


@router.post("/", status_code=status.HTTP_201_CREATED)
async def upload_and_analyze_file(
    file: UploadFile = File(...),
    analysis_service: AnalysisService = Depends(get_analysis_service),
    model_service: ModelService = Depends(get_model_service),
):
    """
    Upload a malware file to CAPEv2 server for analysis, parse the result,
    and process with AI model.
    """
    try:
        cape_report = await analysis_service.upload_and_analyze(file)
        if cape_report is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to get CAPEv2 analysis report",
            )

        # Placeholder for parsing logic
        # parsed_data = await analysis_service.parse_cape_report(cape_report)
        # parsed_data = cape_report

        # Load the standard prompt from file
        with open("standard_prompt.md", "r") as f:
            prompt = f.read()

        ai_result = await model_service.process_request(
            prompt=prompt, file_content=None, filename=None
        )

        return {"status": "success", "cape_report": cape_report, "ai_result": ai_result}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        ) from e
