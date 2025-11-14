import json
from pathlib import Path

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
    return ParserService(models_dir=Path("app/models"))


@router.post("/", status_code=status.HTTP_201_CREATED)
async def upload_and_analyze_file(
    file: UploadFile = File(...),
    analysis_service: AnalysisService = Depends(get_analysis_service),
    model_service: ModelService = Depends(get_model_service),
    parser_service: ParserService = Depends(get_parser_service),
):
    """
    Upload a malware file to CAPEv2 server for analysis, parse the result,
    and process with AI model.
    """
    try:
        # --- STEP 1: use analysis service ---
        # --- STEP 2: use parser service ---
        # --- STEP 3: use model service ---

        print("working")

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        ) from e
