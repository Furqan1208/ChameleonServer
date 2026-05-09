from datetime import datetime, timezone
from typing import Annotated, Optional

from pydantic import BaseModel, BeforeValidator, ConfigDict, EmailStr, Field

PyObjectId = Annotated[str, BeforeValidator(str)]


class UserModel(BaseModel):
    # Mapping MongoDB's "_id" to our "id" field
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    name: str
    email: EmailStr
    google_id: str
    profile_picture: Optional[str] = None
    role: Optional[str] = None
    company: Optional[str] = None
    experience_level: Optional[str] = None
    primary_focus: Optional[str] = None
    onboarding_completed: bool = False
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
    google_id: str
    profile_picture: Optional[str] = None
    role: Optional[str] = None
    company: Optional[str] = None
    experience_level: Optional[str] = None
    primary_focus: Optional[str] = None
    onboarding_completed: bool = False
    threat_intel_queries_total: int = 0
    threat_intel_queries_today: int = 0
    threat_intel_queries_date: Optional[str] = None
    api_keys: Optional[dict] = Field(default_factory=dict)
    ui_preferences: Optional[dict] = Field(default_factory=dict)


class UserUpdate(BaseModel):
    name: Optional[str] = None
    profile_picture: Optional[str] = None
    role: Optional[str] = None
    company: Optional[str] = None
    experience_level: Optional[str] = None
    primary_focus: Optional[str] = None
    onboarding_completed: Optional[bool] = None
    threat_intel_queries_total: Optional[int] = None
    threat_intel_queries_today: Optional[int] = None
    threat_intel_queries_date: Optional[str] = None
    api_keys: Optional[dict] = None
    ui_preferences: Optional[dict] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserModel
