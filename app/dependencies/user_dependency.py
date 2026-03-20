from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.models.user import UserModel
from app.services.user_service import UserService
from app.utils.security import decode_access_token

bearer_scheme = HTTPBearer()
optional_bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> UserModel:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise unauthorized

    user_id = payload.get("sub")
    if not isinstance(user_id, str):
        raise unauthorized

    user = await UserService(db).get_user_by_id(user_id)
    if user is None:
        raise unauthorized

    return user


async def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Depends(optional_bearer_scheme),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> UserModel | None:
    """Resolve user when a bearer token is present, otherwise continue anonymously."""
    if not credentials:
        return None

    payload = decode_access_token(credentials.credentials)
    if not payload:
        return None

    user_id = payload.get("sub")
    if not isinstance(user_id, str):
        return None

    return await UserService(db).get_user_by_id(user_id)
