from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.dependencies.user_dependency import get_current_user
from app.models.user import TokenResponse, UserCreate, UserModel
from app.services.user_service import UserService
from app.utils.security import create_access_token, verify_google_token

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/google", response_model=TokenResponse)
async def google_auth(
    token_data: dict,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Called by the frontend after Google Sign-In.
    Expects: { "id_token": "<google id token>" }
    Returns: JWT access token + user object
    """
    google_id_token = token_data.get("id_token")
    if not google_id_token:
        raise HTTPException(status_code=400, detail="id_token is required")

    google_info = verify_google_token(google_id_token)
    if not google_info:
        raise HTTPException(status_code=401, detail="Invalid Google token")

    user_data = UserCreate(
        name=google_info.get("name", ""),
        email=google_info["email"],
        google_id=google_info["sub"],
        profile_picture=google_info.get("picture"),
    )

    user = await UserService(db).get_or_create_google_user(user_data)
    access_token = create_access_token(data={"sub": user.id})

    return TokenResponse(access_token=access_token, user=user)


@router.get("/me", response_model=UserModel)
async def get_me(current_user: UserModel = Depends(get_current_user)):
    """Returns the currently authenticated user. Use this on frontend page load to restore session."""
    return current_user
