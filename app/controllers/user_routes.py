from fastapi import APIRouter, Depends, HTTPException, status
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.dependencies.user_dependency import get_current_user
from app.models.user import (
    AdminUserStatusRequest,
    ChangePasswordRequest,
    SetPasswordRequest,
    UserModel,
    UserUpdate,
)
from app.services.user_service import UserService
from app.utils.security import validate_password
from app.services.database_service import DatabaseService

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)


async def get_user_service(db: AsyncIOMotorDatabase = Depends(get_database)):
    return UserService(db)


async def get_db_service(db: AsyncIOMotorDatabase = Depends(get_database)):
    return DatabaseService(db)


@router.get("/admin/all", response_model=list[UserModel])
async def list_all_users(
    current_user: UserModel = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Admin-only endpoint to list all users (for password reset management)"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can list all users"
        )
    
    user_service = UserService(db)
    users_collection = db.users
    
    # Get all users from database
    all_users = []
    async for user_dict in users_collection.find():
        all_users.append(UserModel.model_validate(user_dict))
    
    return all_users


@router.get("/admin/{user_id}/reports")
async def get_user_reports(
    user_id: str,
    limit: int = 100,
    skip: int = 0,
    current_user: UserModel = Depends(get_current_user),
    db_service: DatabaseService = Depends(get_db_service),
):
    """Admin-only: fetch analysis reports for a specific user."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can view user reports",
        )

    if not ObjectId.is_valid(user_id):
        raise HTTPException(status_code=400, detail="Invalid user ID")

    reports = await db_service.get_all_analyses(user_id=user_id, limit=limit, skip=skip)
    total = await db_service.get_analysis_count(user_id=user_id)
    return {
        "status": "success",
        "data": reports,
        "count": len(reports),
        "total": total,
        "limit": limit,
        "skip": skip,
    }


@router.patch("/admin/{user_id}/status", response_model=UserModel)
async def update_user_status(
    user_id: str,
    payload: AdminUserStatusRequest,
    current_user: UserModel = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
):
    """Admin-only: enable/disable a user account."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can update user status",
        )

    updated = await user_service.set_user_active(user_id, payload.is_active)
    if updated is None:
        raise HTTPException(status_code=404, detail="User not found")
    return updated


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

    # Prevent users from elevating privileges or disabling accounts
    sanitized = UserUpdate(
        **user_update.model_dump(exclude={"is_admin", "is_active"}, exclude_unset=True)
    )

    # We can pass current_user.id directly because it's already a string
    try:
        updated = await user_service.update_user(current_user.id, sanitized)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

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


@router.post("/me/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    current_user: UserModel = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
):
    if not current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID is missing from profile",
        )

    if not current_user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is not set for this account",
        )

    try:
        validate_password(payload.new_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    success = await user_service.change_password(
        current_user.id,
        payload.current_password,
        payload.new_password,
    )
    if not success:
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    return {"message": "Password updated successfully"}


@router.post("/me/set-password")
async def set_password(
    payload: SetPasswordRequest,
    current_user: UserModel = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
):
    """Set initial password for users without one (e.g., Google OAuth users)."""
    if not current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID is missing from profile",
        )

    if current_user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is already set. Use change-password instead.",
        )

    try:
        validate_password(payload.new_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Use the user service to reset/hash the password (reuses truncation and hashing logic)
    success = await user_service.reset_user_password(current_user.id, payload.new_password)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to set password")

    # Fetch updated user to return
    updated = await user_service.get_user_by_id(current_user.id)
    if updated:
        updated.has_password = bool(updated.hashed_password)

    return {"message": "Password set successfully", "user": updated}


@router.get("/api-keys")
async def get_api_keys(
    current_user: UserModel = Depends(get_current_user),
):
    """Get masked API keys for current user"""
    if not current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID is missing from profile",
        )
    
    api_keys = current_user.api_keys or {}
    masked_keys = {}
    
    # Return masked keys (show only last 4 chars)
    for service, key in api_keys.items():
        if isinstance(key, str) and len(key) > 4:
            masked_keys[service] = f"***{key[-4:]}"
        else:
            masked_keys[service] = "***"
    
    return {"api_keys": masked_keys}


@router.put("/api-keys")
async def update_api_keys(
    api_keys: dict,
    current_user: UserModel = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
):
    """Update API keys for current user"""
    if not current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID is missing from profile",
        )
    
    # Validate each API key is not empty
    for service, key in api_keys.items():
        if not key or not isinstance(key, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid API key for service '{service}'",
            )
    
    # Merge with existing keys
    current_keys = current_user.api_keys or {}
    current_keys.update(api_keys)
    
    user_update = UserUpdate(api_keys=current_keys)
    updated = await user_service.update_user(current_user.id, user_update)
    
    if updated is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Return masked response
    masked_keys = {}
    for service, key in (updated.api_keys or {}).items():
        if isinstance(key, str) and len(key) > 4:
            masked_keys[service] = f"***{key[-4:]}"
        else:
            masked_keys[service] = "***"
    
    return {
        "message": "API keys updated successfully",
        "api_keys": masked_keys
    }


@router.delete("/api-keys/{service}")
async def delete_api_key(
    service: str,
    current_user: UserModel = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
):
    """Delete specific API key"""
    if not current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID is missing from profile",
        )
    
    api_keys = current_user.api_keys or {}
    
    if service not in api_keys:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key for service '{service}' not found",
        )
    
    del api_keys[service]
    
    user_update = UserUpdate(api_keys=api_keys)
    updated = await user_service.update_user(current_user.id, user_update)
    
    if updated is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": f"API key for {service} deleted successfully"}


# ── UI Preferences ───────────────────────────────────────────────────────────


@router.get("/preferences")
async def get_preferences(
    current_user: UserModel = Depends(get_current_user),
):
    """Get user UI preferences with defaults for missing fields"""
    if not current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID is missing from profile",
        )

    # Return preferences or empty dict (frontend fills in defaults)
    return current_user.ui_preferences or {}


@router.put("/preferences")
async def update_preferences(
    preferences: dict,
    current_user: UserModel = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
):
    """Update user UI preferences (sidebar, tabs, theme, etc.)"""
    if not current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID is missing from profile",
        )

    # Merge with existing preferences instead of replacing
    current_prefs = current_user.ui_preferences or {}
    current_prefs.update(preferences)

    user_update = UserUpdate(ui_preferences=current_prefs)
    updated = await user_service.update_user(current_user.id, user_update)

    if updated is None:
        raise HTTPException(status_code=404, detail="User not found")

    return {"preferences": updated.ui_preferences or {}}
