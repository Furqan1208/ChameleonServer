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
