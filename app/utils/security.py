from datetime import datetime, timedelta
from typing import Optional

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from jose import JWTError, jwt

from app.config.config import settings


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(
        to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


def decode_access_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except JWTError:
        return None


def verify_google_token(google_id_token: str) -> Optional[dict]:
    try:
        id_info = id_token.verify_oauth2_token(
            google_id_token,
            google_requests.Request(),
            settings.GOOGLE_CLIENT_ID,
        )
        if id_info.get("aud") != settings.GOOGLE_CLIENT_ID:
            return None
        return id_info
    except ValueError:
        return None
