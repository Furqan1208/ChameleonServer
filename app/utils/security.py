import base64
from io import BytesIO
from datetime import datetime, timedelta
from typing import Optional

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from jose import JWTError, jwt
from passlib.context import CryptContext
import pyotp
import qrcode

from app.config.config import settings

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt. Automatically truncates to 72 bytes (bcrypt limit)."""
    # Bcrypt has a 72-byte limit, truncate silently
    truncated = password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
    return pwd_context.hash(truncated)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash. Automatically truncates to 72 bytes (bcrypt limit)."""
    # Bcrypt has a 72-byte limit, truncate silently
    truncated = plain_password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
    return pwd_context.verify(truncated, hashed_password)


def validate_password(password: str) -> None:
    """Validate password requirements: 8+ chars, at least 1 number, at least 1 symbol"""
    import re

    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")

    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one number")

    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};:'\"\\|,.<>\/?]", password):
        raise ValueError("Password must contain at least one symbol (!@#$%^&* etc)")


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


def create_mfa_secret() -> str:
    return pyotp.random_base32()


def build_mfa_otpauth_uri(secret: str, account_name: str, issuer: str = "Chameleon") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer)


def build_qr_code_data_url(payload: str) -> str:
    qr_code = qrcode.make(payload)
    buffer = BytesIO()
    qr_code.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def verify_totp_code(secret: str, code: str) -> bool:
    token = code.strip().replace(" ", "")
    if not token.isdigit():
        return False
    return pyotp.TOTP(secret).verify(token, valid_window=1)


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
