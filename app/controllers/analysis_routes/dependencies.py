from pathlib import Path

from fastapi import Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.services.ai_analysis_service import AIAnalysisService
from app.services.cape_analysis_service import CapeAnalysisService
from app.services.chunking_service import ChunkingService
from app.services.model_service import ModelService
from app.services.parser_service import ParserService


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
