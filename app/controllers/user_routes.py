from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.dependencies.user_dependency import get_current_user
from app.models.user import UserModel, UserUpdate
from app.services.user_service import UserService

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)


async def get_user_service(db: AsyncIOMotorDatabase = Depends(get_database)):
    return UserService(db)


@router.get("/me", response_model=UserModel)
async def read_current_user(
    current_user: UserModel = Depends(get_current_user),
):
    return current_user


@router.put("/me", response_model=UserModel)
async def update_current_user(
    user_update: UserUpdate,
    current_user: UserModel = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
):
    # This check satisfies Pylance regarding the Optional[str] type
    if not current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID is missing from profile",
        )

    # We can pass current_user.id directly because it's already a string
    updated = await user_service.update_user(current_user.id, user_update)

    if updated is None:
        raise HTTPException(status_code=404, detail="User not found")
    return updated


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_current_user(
    current_user: UserModel = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
):
    if not current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID is missing from profile",
        )

    success = await user_service.delete_user(current_user.id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found or already deleted")

    return None
