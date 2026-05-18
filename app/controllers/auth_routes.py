from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.dependencies.user_dependency import get_current_user
from app.models.user import (
    AuthResponse,
    MfaSetupConfirmRequest,
    MfaSetupResponse,
    MfaVerifyRequest,
    TokenResponse,
    UserCreate,
    UserModel,
    RegisterRequest,
    LoginRequest,
)
from app.services.user_service import UserService
from app.utils.security import (
    build_mfa_otpauth_uri,
    build_qr_code_data_url,
    create_access_token,
    create_mfa_secret,
    decode_access_token,
    validate_password,
    verify_google_token,
    verify_totp_code,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def build_auth_response(
    user: UserModel,
    access_token: str | None = None,
    mfa_required: bool = False,
    mfa_token: str | None = None,
) -> AuthResponse:
    return AuthResponse(
        access_token=access_token,
        user=user,
        mfa_required=mfa_required,
        mfa_token=mfa_token,
    )


def create_mfa_challenge(user: UserModel) -> AuthResponse:
    mfa_token = create_access_token(
        data={"sub": user.id, "purpose": "mfa_challenge"},
        expires_delta=timedelta(minutes=10),
    )
    return build_auth_response(user=user, mfa_required=True, mfa_token=mfa_token)


@router.post("/google", response_model=AuthResponse)
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

    user_service = UserService(db)
    user = await user_service.get_or_create_google_user(user_data)
    user = await user_service.ensure_admin_by_email(user)
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    if user.mfa_enabled and user.mfa_secret:
        return create_mfa_challenge(user)

    access_token = create_access_token(data={"sub": user.id})
    user.has_password = bool(user.hashed_password)

    return build_auth_response(user=user, access_token=access_token)


@router.post("/register", response_model=TokenResponse)
async def register(
    req: RegisterRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Register a new user with email, name, username, and password.
    Returns JWT access token + user object
    """
    # Truncate password to 72 bytes (bcrypt limit) before any processing
    truncated_password = req.password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
    
    user_service = UserService(db)

    try:
        validate_password(truncated_password)
        user = await user_service.register_user(
            name=req.name,
            email=req.email,
            username=req.username,
            password=truncated_password,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    access_token = create_access_token(data={"sub": user.id})
    user.has_password = bool(user.hashed_password)
    return TokenResponse(access_token=access_token, user=user)


@router.post("/login", response_model=AuthResponse)
async def login(
    req: LoginRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Authenticate user with username and password.
    Returns JWT access token + user object
    """
    user_service = UserService(db)
    user = await user_service.authenticate_user(req.username, req.password)

    if not user:
        raise HTTPException(
            status_code=401, detail="Invalid username or password"
        )

    # Check if user account is active (disabled users cannot login)
    if not user.is_active:
        raise HTTPException(
            status_code=403, detail="Your account has been disabled. Please contact the administrator."
        )

    if user.mfa_enabled and user.mfa_secret:
        return create_mfa_challenge(user)

    access_token = create_access_token(data={"sub": user.id})
    user.has_password = bool(user.hashed_password)
    return build_auth_response(user=user, access_token=access_token)


@router.post("/mfa/verify", response_model=TokenResponse)
async def verify_mfa(
    req: MfaVerifyRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    challenge = decode_access_token(req.mfa_token)
    if not challenge:
        raise HTTPException(status_code=401, detail="Invalid MFA challenge")

    if challenge.get("purpose") != "mfa_challenge":
        raise HTTPException(status_code=401, detail="Invalid MFA challenge")

    user_id = challenge.get("sub")
    if not isinstance(user_id, str):
        raise HTTPException(status_code=401, detail="Invalid MFA challenge")

    user_service = UserService(db)
    user = await user_service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid MFA challenge")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Your account has been disabled. Please contact the administrator.")

    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA is not enabled for this account")

    if not verify_totp_code(user.mfa_secret, req.code):
        raise HTTPException(status_code=401, detail="Invalid authentication code")

    access_token = create_access_token(data={"sub": user.id})
    user.has_password = bool(user.hashed_password)
    return TokenResponse(access_token=access_token, user=user)


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def setup_mfa(
    current_user: UserModel = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    secret = create_mfa_secret()
    user_service = UserService(db)
    updated = await user_service.set_user_mfa_secret(current_user.id, secret)
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")

    issuer = "Chameleon"
    otpauth_uri = build_mfa_otpauth_uri(secret, current_user.email, issuer=issuer)
    qr_code_data_url = build_qr_code_data_url(otpauth_uri)

    return MfaSetupResponse(
        secret=secret,
        otpauth_uri=otpauth_uri,
        qr_code_data_url=qr_code_data_url,
        issuer=issuer,
    )


@router.post("/mfa/confirm", response_model=UserModel)
async def confirm_mfa(
    req: MfaSetupConfirmRequest,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA setup has not been started")

    if not verify_totp_code(current_user.mfa_secret, req.code):
        raise HTTPException(status_code=400, detail="Invalid authentication code")

    user_service = UserService(db)
    updated = await user_service.enable_user_mfa(current_user.id)
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")

    updated.has_password = bool(updated.hashed_password)
    return updated


@router.post("/mfa/disable", response_model=UserModel)
async def disable_mfa(
    current_user: UserModel = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    user_service = UserService(db)
    updated = await user_service.disable_user_mfa(current_user.id)
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")

    updated.has_password = bool(updated.hashed_password)
    return updated


@router.get("/me", response_model=UserModel)
async def get_me(current_user: UserModel = Depends(get_current_user)):
    """Returns the currently authenticated user. Use this on frontend page load to restore session."""
    current_user.has_password = bool(current_user.hashed_password)
    return current_user


@router.post("/admin/reset-password")
async def admin_reset_password(
    request: Request,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Admin-only endpoint to reset a user's password.
    Only users with is_admin=True can use this.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=403, detail="Only admins can reset passwords"
        )

    payload = await request.json()

    # Accept both snake_case and camelCase client keys
    user_id = payload.get("user_id") or payload.get("userId")
    new_password = payload.get("new_password") or payload.get("newPassword")

    if not user_id or not isinstance(user_id, str):
        raise HTTPException(status_code=400, detail="user_id is required")

    if not new_password or not isinstance(new_password, str):
        raise HTTPException(status_code=400, detail="new_password is required")

    # Truncate password to 72 bytes (bcrypt limit) before any processing
    truncated_password = new_password.encode('utf-8')[:72].decode('utf-8', errors='ignore')

    try:
        validate_password(truncated_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    user_service = UserService(db)
    success = await user_service.reset_user_password(user_id, truncated_password)

    if not success:
        raise HTTPException(status_code=404, detail="User not found")

    return {"message": "Password reset successfully"}

