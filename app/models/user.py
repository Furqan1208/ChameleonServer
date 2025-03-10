# Import necessary modules from Pydantic, typing, datetime, and bson.
from pydantic import BaseModel, Field, EmailStr, root_validator
from typing import Optional, List
from datetime import datetime
from bson import ObjectId

# Custom type for MongoDB ObjectId that works with Pydantic v2.
class PyObjectId(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    # Validator for ObjectId: accepts the value and context info.
    @classmethod
    def validate(cls, v, info):
        # Check if the value is a valid ObjectId.
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        # Return the value as a string.
        return str(v)

# Main Pydantic model for a user.
class UserModel(BaseModel):
    # MongoDB _id field mapped to "id" (alias "_id").
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    # Required user name field. If missing, we attempt to populate it from "username".
    name: str
    # Email field with built-in email validation.
    email: EmailStr
    # Optional profile picture URL.
    profile_picture: Optional[str] = None
    # List of favorite PaperSummary ObjectIds; defaults to an empty list.
    favorites: Optional[List[PyObjectId]] = Field(default_factory=list)
    # Automatically set the creation timestamp.
    created_at: datetime = Field(default_factory=datetime.utcnow)
    # Optional field for the last update timestamp.
    updated_at: Optional[datetime] = None

    # Root validator to handle legacy documents.
    @root_validator(pre=True)
    def populate_name(cls, values):
        # If "name" is not provided but "username" exists, use "username" as the name.
        if "name" not in values and "username" in values:
            values["name"] = values["username"]
        return values

    class Config:
        # Allow using field names instead of aliases during population.
        populate_by_name = True
        # Schema example for documentation purposes.
        json_schema_extra = {
            "example": {
                "name": "John Doe",
                "email": "johndoe@example.com",
                "profile_picture": "https://example.com/profile.jpg",
                "favorites": [],
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }

# Model for creating a new user.
class UserCreate(BaseModel):
    # "name" is required when creating a user.
    name: str
    # Email field for the new user.
    email: EmailStr
    # Optional profile picture URL.
    profile_picture: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "name": "John Doe",
                "email": "johndoe@example.com",
                "profile_picture": "https://example.com/profile.jpg"
            }
        }

# Model for updating an existing user. All fields are optional.
class UserUpdate(BaseModel):
    name: Optional[str] = None          
