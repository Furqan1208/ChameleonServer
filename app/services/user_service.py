from datetime import datetime, timezone
from typing import Optional
import re

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.user import UserCreate, UserModel, UserUpdate
from app.utils.security import get_password_hash, verify_password


class UserService:
    def __init__(self, database: AsyncIOMotorDatabase):
        self.database = database
        self.collection = database.users
        self.admin_email = "mfurqanpatel61@gmail.com"

    async def get_user_by_id(self, user_id: str) -> Optional[UserModel]:
        if not ObjectId.is_valid(user_id):
            return None

        user_dict = await self.collection.find_one({"_id": ObjectId(user_id)})
        if user_dict:
            return UserModel.model_validate(user_dict)
        return None

    async def get_user_by_email(self, email: str) -> Optional[UserModel]:
        # Case-insensitive lookup to avoid duplicates with different casing
        query = {"email": {"$regex": f'^{re.escape(email)}$', "$options": "i"}}
        user_dict = await self.collection.find_one(query)
        if user_dict:
            return UserModel.model_validate(user_dict)
        return None

    async def get_user_by_google_id(self, google_id: str) -> Optional[UserModel]:
        user_dict = await self.collection.find_one({"google_id": google_id})
        if user_dict:
            return UserModel.model_validate(user_dict)
        return None

    async def get_user_by_username(self, username: str) -> Optional[UserModel]:
        """Get user by username (for username/password authentication)"""
        # Case-insensitive lookup for usernames to prevent duplicates differing only by case
        query = {"username": {"$regex": f'^{re.escape(username)}$', "$options": "i"}}
        user_dict = await self.collection.find_one(query)
        if user_dict:
            return UserModel.model_validate(user_dict)
        return None

    async def get_or_create_google_user(self, user_data: UserCreate) -> UserModel:
        existing = await self.get_user_by_google_id(user_data.google_id)
        if existing:
            return existing

        email_user = await self.get_user_by_email(user_data.email)
        if email_user:
            await self.collection.update_one(
                {"email": user_data.email}, {"$set": {"google_id": user_data.google_id}}
            )
            updated = await self.get_user_by_email(user_data.email)
            if updated:
                return updated
            raise RuntimeError("Failed to retrieve user after linking Google ID")

        return await self.create_user(user_data)

    async def ensure_admin_by_email(self, user: UserModel) -> UserModel:
        """Ensure admin flag is enabled for the configured admin email."""
        if not user.id:
            return user

        if user.email.lower() == self.admin_email.lower() and not user.is_admin:
            await self.collection.update_one(
                {"_id": ObjectId(user.id)}, {"$set": {"is_admin": True}}
            )
            refreshed = await self.get_user_by_id(user.id)
            return refreshed or user
        return user

    async def create_user(self, user: UserCreate) -> UserModel:
        user_data = user.model_dump()
        user_data["created_at"] = datetime.now(timezone.utc)
        # Enforce uniqueness of email and username at application level
        email = user_data.get("email")
        username = user_data.get("username")
        if email:
            existing_email = await self.get_user_by_email(email)
            if existing_email:
                raise ValueError("Email already registered")
        if username:
            existing_username = await self.get_user_by_username(username)
            if existing_username:
                raise ValueError("Username already taken")

        result = await self.collection.insert_one(user_data)
        created = await self.collection.find_one({"_id": result.inserted_id})

        if not created:
            raise RuntimeError("Database error during user creation")

        return UserModel.model_validate(created)

    async def update_user(
        self, user_id: str, user_update: UserUpdate
    ) -> Optional[UserModel]:
        if not ObjectId.is_valid(user_id):
            return None

        # exclude_unset=True ensures we only update fields provided in the request
        update_data = {
            k: v
            for k, v in user_update.model_dump(exclude_unset=True).items()
            if v is not None
        }

        # Treat role submission as onboarding completion.
        if update_data.get("role"):
            update_data["onboarding_completed"] = True

        if update_data:
            # If username/email being updated, ensure uniqueness
            if update_data.get("username"):
                existing = await self.get_user_by_username(update_data.get("username"))
                if existing and existing.id != user_id:
                    raise ValueError("Username already taken")
            if update_data.get("email"):
                existing = await self.get_user_by_email(update_data.get("email"))
                if existing and existing.id != user_id:
                    raise ValueError("Email already registered")

            await self.collection.update_one(
                {"_id": ObjectId(user_id)}, {"$set": update_data}
            )

        updated = await self.collection.find_one({"_id": ObjectId(user_id)})
        return UserModel.model_validate(updated) if updated else None

    async def delete_user(self, user_id: str) -> bool:
        if not ObjectId.is_valid(user_id):
            return False

        result = await self.collection.delete_one({"_id": ObjectId(user_id)})
        return result.deleted_count > 0

    async def register_user(
        self,
        name: str,
        email: str,
        username: str,
        password: str,
    ) -> UserModel:
        """Register a new user with username and password"""
        # Truncate password to 72 bytes (bcrypt limit)
        truncated_password = password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
        
        # Check if username already exists
        existing_user = await self.get_user_by_username(username)
        if existing_user:
            raise ValueError("Username already taken")

        # Check if email already exists
        existing_email = await self.get_user_by_email(email)
        if existing_email:
            raise ValueError("Email already registered")

        # Create new user with hashed password
        user_data = UserCreate(
            name=name,
            email=email,
            username=username,
            hashed_password=get_password_hash(truncated_password),
            is_admin=(email.lower() == self.admin_email.lower()),
        )

        return await self.create_user(user_data)

    async def authenticate_user(
        self, username: str, password: str
    ) -> Optional[UserModel]:
        """Authenticate user with username and password"""
        # Truncate password to 72 bytes (bcrypt limit)
        truncated_password = password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
        
        # Allow login with either username or email
        user = await self.get_user_by_username(username)
        if not user:
            user = await self.get_user_by_email(username)
        if not user:
            return None

        if not user.hashed_password:
            return None

        # Verify password first (do not check is_active here - let the controller handle disabled accounts)
        if not verify_password(truncated_password, user.hashed_password):
            return None

        return await self.ensure_admin_by_email(user)

    async def update_user_mfa(
        self,
        user_id: str,
        *,
        mfa_enabled: bool,
        mfa_secret: Optional[str] = None,
    ) -> Optional[UserModel]:
        if not ObjectId.is_valid(user_id):
            return None

        await self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"mfa_enabled": mfa_enabled, "mfa_secret": mfa_secret}},
        )
        updated = await self.collection.find_one({"_id": ObjectId(user_id)})
        return UserModel.model_validate(updated) if updated else None

    async def set_user_mfa_secret(
        self,
        user_id: str,
        mfa_secret: str,
    ) -> Optional[UserModel]:
        return await self.update_user_mfa(
            user_id,
            mfa_enabled=False,
            mfa_secret=mfa_secret,
        )

    async def enable_user_mfa(self, user_id: str) -> Optional[UserModel]:
        if not ObjectId.is_valid(user_id):
            return None

        updated = await self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"mfa_enabled": True}},
        )
        if updated.matched_count == 0:
            return None

        user_dict = await self.collection.find_one({"_id": ObjectId(user_id)})
        return UserModel.model_validate(user_dict) if user_dict else None

    async def disable_user_mfa(self, user_id: str) -> Optional[UserModel]:
        if not ObjectId.is_valid(user_id):
            return None

        updated = await self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"mfa_enabled": False}, "$unset": {"mfa_secret": ""}},
        )
        if updated.matched_count == 0:
            return None

        user_dict = await self.collection.find_one({"_id": ObjectId(user_id)})
        return UserModel.model_validate(user_dict) if user_dict else None

    async def set_user_active(self, user_id: str, is_active: bool) -> Optional[UserModel]:
        if not ObjectId.is_valid(user_id):
            return None

        await self.collection.update_one(
            {"_id": ObjectId(user_id)}, {"$set": {"is_active": is_active}}
        )
        updated = await self.collection.find_one({"_id": ObjectId(user_id)})
        return UserModel.model_validate(updated) if updated else None

    async def change_password(
        self, user_id: str, current_password: str, new_password: str
    ) -> bool:
        if not ObjectId.is_valid(user_id):
            return False

        user = await self.get_user_by_id(user_id)
        if not user or not user.hashed_password:
            return False

        truncated_current = current_password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
        if not verify_password(truncated_current, user.hashed_password):
            return False

        truncated_new = new_password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
        hashed_password = get_password_hash(truncated_new)
        result = await self.collection.update_one(
            {"_id": ObjectId(user_id)}, {"$set": {"hashed_password": hashed_password}}
        )
        return result.modified_count > 0

    async def reset_user_password(self, user_id: str, new_password: str) -> bool:
        """Reset a user's password (admin-only operation)"""
        # Truncate password to 72 bytes (bcrypt limit)
        truncated_password = new_password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
        
        if not ObjectId.is_valid(user_id):
            return False

        hashed_password = get_password_hash(truncated_password)
        result = await self.collection.update_one(
            {"_id": ObjectId(user_id)}, {"$set": {"hashed_password": hashed_password}}
        )

        return result.modified_count > 0
