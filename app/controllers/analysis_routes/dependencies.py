from pathlib import Path

from fastapi import Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.dependencies.user_dependency import get_current_user
from app.models.user import UserModel
from app.services.ai_analysis_service import AIAnalysisService
from app.services.cape_analysis_service import CapeAnalysisService
from app.services.chunking_service import ChunkingService
from app.services.database_service import DatabaseService
from app.services.model_service import ModelService
from app.services.parser_service import ParserService


async def get_analysis_user(
    current_user: UserModel = Depends(get_current_user),
) -> UserModel:
    """
    Re-exports get_current_user for sub-routes that need the full UserModel.
    FastAPI deduplicates Depends(get_current_user) within the same request,
    so no extra DB call is made beyond the parent router's auth guard.
    """
    return current_user


async def get_current_user_id(
    current_user: UserModel = Depends(get_current_user),
) -> str:
    """
    Returns a guaranteed non-null user ID string.
    Use this in routes that only need the user_id, not the full UserModel.
    Centralizes the None check so Pylance is satisfied and routes stay clean.
    """
    if not current_user.id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not resolve user identity",
        )
    return current_user.id


async def get_db_service(
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> DatabaseService:
    return DatabaseService(db)


async def get_analysis_service(
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> CapeAnalysisService:
    return CapeAnalysisService(db)


async def get_parser_service() -> ParserService:
    return ParserService(models_dir=Path("app/parser"))


def get_model_service() -> ModelService:
    """ModelService configures itself from environment variables."""
    return ModelService()


def get_chunking_service() -> ChunkingService:
    """ChunkingService configures itself from constants — no args needed."""
    return ChunkingService()


async def get_ai_analysis_service(
    model_service: ModelService = Depends(get_model_service),
    parser_service: ParserService = Depends(get_parser_service),
    chunking_service: ChunkingService = Depends(get_chunking_service),
) -> AIAnalysisService:
    return AIAnalysisService(model_service, parser_service, chunking_service)
