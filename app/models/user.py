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


class UserUpdate(BaseModel):
    name: Optional[str] = None
    profile_picture: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserModel
