from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.models.user import UserCreate, UserModel, UserUpdate
from app.services.user_service import UserService

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)


async def get_user_service(db: AsyncIOMotorDatabase = Depends(get_database)):
    return UserService(db)


@router.get("/", response_model=List[UserModel])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    user_service: UserService = Depends(get_user_service),
):
    """
    Retrieve all users.
    """
    return await user_service.get_all_users(skip=skip, limit=limit)


@router.get("/{user_id}", response_model=UserModel)
async def read_user(
    user_id: str, user_service: UserService = Depends(get_user_service)
):
    """
    Retrieve a specific user by ID.
    """
    user = await user_service.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.post("/", response_model=UserModel, status_code=status.HTTP_201_CREATED)
async def create_user(
    user: UserCreate, user_service: UserService = Depends(get_user_service)
):
    """
    Create a new user.
    """
    # Check if user with the same email already exists
    existing_user = await user_service.get_user_by_email(user.email)
    if existing_user:
        raise HTTPException(
            status_code=400, detail="User with this email already exists"
        )

    return await user_service.create_user(user)


@router.put("/{user_id}", response_model=UserModel)
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    user_service: UserService = Depends(get_user_service),
):
    """
    Update an existing user.
    """
    updated_user = await user_service.update_user(user_id, user_update)
    if updated_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return updated_user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str, user_service: UserService = Depends(get_user_service)
):
    """
    Delete a user.
    """
    deleted = await user_service.delete_user(user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")
    return None
