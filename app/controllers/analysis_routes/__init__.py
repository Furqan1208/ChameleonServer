from fastapi import APIRouter, Depends

from app.dependencies.user_dependency import get_current_user

from .ai import router as ai_router
from .complete import router as complete_router
from .parse import router as parse_router
from .reports import router as reports_router

router = APIRouter(
    prefix="/analysis",
    tags=["analysis"],
    responses={404: {"description": "Not found"}},
    dependencies=[Depends(get_current_user)],  # auth guard only — result discarded
)

router.include_router(complete_router)
router.include_router(parse_router)
router.include_router(ai_router)
router.include_router(reports_router)

__all__ = ["router"]
