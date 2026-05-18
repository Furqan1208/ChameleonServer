from datetime import datetime, timezone
from typing import Annotated, Optional

from pydantic import BaseModel, BeforeValidator, ConfigDict, EmailStr, Field

PyObjectId = Annotated[str, BeforeValidator(str)]


class UserModel(BaseModel):
    # Mapping MongoDB's "_id" to our "id" field
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    name: str
    email: EmailStr
    # Google OAuth fields
    google_id: Optional[str] = None
    # Username/Password auth fields
    username: Optional[str] = None  # For normal registration
    hashed_password: Optional[str] = Field(default=None, exclude=True)  # For username/password auth
    has_password: bool = False
    profile_picture: Optional[str] = None
    role: Optional[str] = None
    company: Optional[str] = None
    experience_level: Optional[str] = None
    primary_focus: Optional[str] = None
    onboarding_completed: bool = False
    # MFA / TOTP authentication
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = Field(default=None, exclude=True)
    # Admin functionality
    is_admin: bool = False  # Set to True for mfurqanpatel61@gmail.com
    is_active: bool = True
    threat_intel_queries_total: int = 0
    threat_intel_queries_today: int = 0
    threat_intel_queries_date: Optional[str] = None
    # API Key Management
    api_keys: Optional[dict] = Field(default_factory=dict)  # Store API keys for integrations
    # UI Preferences - user customizable settings (sidebar, tabs, theme, etc.)
    ui_preferences: Optional[dict] = Field(
        default_factory=dict,
        description="User UI settings: sidebar state, theme, tab preferences, etc.",
    )
    # utcnow() is deprecated in Python 3.12+, so we use timezone-aware datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        from_attributes=True,
    )


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    google_id: Optional[str] = None
    username: Optional[str] = None
    hashed_password: Optional[str] = None
    profile_picture: Optional[str] = None
    role: Optional[str] = None
    company: Optional[str] = None
    experience_level: Optional[str] = None
    primary_focus: Optional[str] = None
    onboarding_completed: bool = False
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = Field(default=None, exclude=True)
    is_admin: bool = False
    is_active: bool = True
    threat_intel_queries_total: int = 0
    threat_intel_queries_today: int = 0
    threat_intel_queries_date: Optional[str] = None
    api_keys: Optional[dict] = Field(default_factory=dict)
    ui_preferences: Optional[dict] = Field(default_factory=dict)


class UserUpdate(BaseModel):
    name: Optional[str] = None
    # Allow updating the hashed password when needed (admin or set-password flows)
    hashed_password: Optional[str] = None
    profile_picture: Optional[str] = None
    role: Optional[str] = None
    company: Optional[str] = None
    experience_level: Optional[str] = None
    primary_focus: Optional[str] = None
    onboarding_completed: Optional[bool] = None
    mfa_enabled: Optional[bool] = None
    mfa_secret: Optional[str] = Field(default=None, exclude=True)
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None
    threat_intel_queries_total: Optional[int] = None
    threat_intel_queries_today: Optional[int] = None
    threat_intel_queries_date: Optional[str] = None
    api_keys: Optional[dict] = None
    ui_preferences: Optional[dict] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserModel


class AuthResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    user: Optional[UserModel] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_code_data_url: str
    issuer: str = "Chameleon"


class MfaVerifyRequest(BaseModel):
    mfa_token: str
    code: str


class MfaSetupConfirmRequest(BaseModel):
    code: str


# Request schemas for authentication
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordResetRequest(BaseModel):
    user_id: str
    new_password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class SetPasswordRequest(BaseModel):
    new_password: str


class AdminUserStatusRequest(BaseModel):
    is_active: bool
