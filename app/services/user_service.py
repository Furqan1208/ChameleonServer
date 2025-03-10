# Import necessary modules and models.
from bson import ObjectId
from app.models.user import UserModel, UserCreate, UserUpdate
from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime
from typing import List, Optional

# Service class to encapsulate user-related database operations.
class UserService:
    def __init__(self, database: AsyncIOMotorDatabase):
        # Initialize with a MongoDB database instance.
        self.database = database
        # Reference to the 'users' collection.
        self.collection = database.users

    # Retrieve all users with optional pagination.
    async def get_all_users(self, skip: int = 0, limit: int = 100) -> List[UserModel]:
        users = []  # List to hold user objects.
        # Create a cursor for MongoDB query with skip and limit.
        cursor = self.collection.find().skip(skip).limit(limit)
        # Iterate asynchronously over the documents.
        async for document in cursor:
            # Convert each document to a UserModel instance.
            users.append(UserModel(**document))
        return users

    # Retrieve a user by their ID.
    async def get_user_by_id(self, user_id: str) -> Optional[UserModel]:
        # Return None if the provided ID is not valid.
        if not ObjectId.is_valid(user_id):
            return None
        # Find the user document by _id.
        user = await self.collection.find_one({"_id": ObjectId(user_id)})
        if user:
            return UserModel(**user)
        return None

    # Retrieve a user by their email address.
    async def get_user_by_email(self, email: str) -> Optional[UserModel]:
        user = await self.collection.find_one({"email": email})
        if user:
            return UserModel(**user)
        return None

    # Create a new user in the database.
    async def create_user(self, user: UserCreate) -> UserModel:
        # Convert the Pydantic model to a dictionary.
        user_data = user.model_dump()
        # Set the creation timestamp.
        user_data["created_at"] = datetime.utcnow()
        # Insert the new user document.
        result = await self.collection.insert_one(user_data)
        # Retrieve the newly created user from the database.
        created_user = await self.collection.find_one({"_id": result.inserted_id})
        return UserModel(**created_user)

    # Update an existing user.
    async def update_user(self, user_id: str, user_update: UserUpdate) -> Optional[UserModel]:
        # Validate the user_id.
        if not ObjectId.is_valid(user_id):
            return None
        # Create a dict with only the fields that have been provided (non-None).
        update_data = {k: v for k, v in user_update.model_dump().items() if v is not None}
        if update_data:
            # Update the document in MongoDB.
            await self.collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": update_data}
            )
        # Retrieve and return the updated user.
        updated_user = await self.collection.find_one({"_id": ObjectId(user_id)})
        if updated_user:
            return UserModel(**updated_user)
        return None

    # Delete a user by their ID.
    async def delete_user(self, user_id: str) -> bool:
        # Return False if the provided ID is not valid.
        if not ObjectId.is_valid(user_id):
            return False
        # Delete the user document from the database.
        result = await self.collection.delete_one({"_id": ObjectId(user_id)})
        # Return True if a document was deleted.
        return result.deleted_count > 0
