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
        # --- STEP 1: Read uploaded file ---
        file_content = await file.read()

        if not file_content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty.",
            )

        # --- STEP 2: (Optional) CAPEv2 analysis logic ---
        # cape_report = await analysis_service.upload_and_analyze(file)
        # if cape_report is None:
        #     raise HTTPException(
        #         status_code=status.HTTP_400_BAD_REQUEST,
        #         detail="Failed to get CAPEv2 analysis report",
        #     )

        # --- STEP 3: Load standard prompt ---
        # with open("app/templates/standard_prompt.md", "r") as f:
        #     prompt = f.read()

        # --- STEP 4: Process file with model service ---
        ai_result = await model_service.process_request(
            prompt="what are you capable of?",
            file_content=file_content,
            filename=file.filename,
        )

        # --- STEP 5: Return response ---
        return {
            "status": "success",
            "ai_result": ai_result,
            "filename": file.filename,
            "file_size_bytes": len(file_content),
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        ) from e
