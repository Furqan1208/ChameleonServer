from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.user import UserCreate, UserModel, UserUpdate


class UserService:
    def __init__(self, database: AsyncIOMotorDatabase):
        self.database = database
        self.collection = database.users

    async def get_user_by_id(self, user_id: str) -> Optional[UserModel]:
        if not ObjectId.is_valid(user_id):
            return None

        user_dict = await self.collection.find_one({"_id": ObjectId(user_id)})
        if user_dict:
            return UserModel.model_validate(user_dict)
        return None

    async def get_user_by_email(self, email: str) -> Optional[UserModel]:
        user_dict = await self.collection.find_one({"email": email})
        if user_dict:
            return UserModel.model_validate(user_dict)
        return None

    async def get_user_by_google_id(self, google_id: str) -> Optional[UserModel]:
        user_dict = await self.collection.find_one({"google_id": google_id})
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

    async def create_user(self, user: UserCreate) -> UserModel:
        user_data = user.model_dump()
        user_data["created_at"] = datetime.now(timezone.utc)

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

        if update_data:
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
