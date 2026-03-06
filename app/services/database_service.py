# D:\FYP\ChameleonServer\app\services\database_service.py
from datetime import datetime
from typing import Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase


class DatabaseService:
    """Service for managing analysis data in MongoDB"""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.cape_collection = db["cape_results"]
        self.parsed_collection = db["parsed_results"]
        self.ai_collection = db["ai_results"]
        self.analyses_collection = db["analyses"]

    # -------------------------------------------------------------------------
    # Private Helpers
    # -------------------------------------------------------------------------

    async def _verify_ownership(self, user_id: str, analysis_id: str) -> bool:
        """Verify that the analysis belongs to the given user"""
        record = await self.analyses_collection.find_one(
            {"analysis_id": analysis_id, "user_id": ObjectId(user_id)},
            {"_id": 1},  # minimal projection
        )
        return record is not None

    # -------------------------------------------------------------------------
    # Write Operations
    # -------------------------------------------------------------------------

    async def create_analysis_record(
        self,
        user_id: str,
        analysis_id: str,
        filename: str,
        analysis_type: str,
        model_name: Optional[str] = None,
    ) -> dict:
        """Create initial analysis record associated with a user"""
        record = {
            "user_id": ObjectId(user_id),
            "analysis_id": analysis_id,
            "filename": filename,
            "analysis_type": analysis_type,
            "model_name": model_name,
            "status": "in_progress",
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "components": {"cape": False, "parsed": False, "ai_analysis": False},
        }

        await self.analyses_collection.insert_one(record)
        return record

    async def save_cape_results(
        self, user_id: str, analysis_id: str, cape_data: dict
    ) -> bool:
        """Save CAPE analysis results"""
        try:
            if not await self._verify_ownership(user_id, analysis_id):
                return False

            document = {
                "analysis_id": analysis_id,
                "data": cape_data,
                "created_at": datetime.now(),
            }

            await self.cape_collection.insert_one(document)

            await self.analyses_collection.update_one(
                {"analysis_id": analysis_id},
                {"$set": {"components.cape": True, "updated_at": datetime.now()}},
            )

            return True
        except Exception as e:
            print(f"Error saving CAPE results: {str(e)}")
            return False

    async def save_parsed_results(
        self, user_id: str, analysis_id: str, parsed_data: dict
    ) -> bool:
        """Save parsed results"""
        try:
            if not await self._verify_ownership(user_id, analysis_id):
                return False

            document = {
                "analysis_id": analysis_id,
                "metadata": parsed_data.get("metadata", {}),
                "sections": parsed_data.get("sections", {}),
                "created_at": datetime.now(),
            }

            await self.parsed_collection.insert_one(document)

            await self.analyses_collection.update_one(
                {"analysis_id": analysis_id},
                {
                    "$set": {
                        "components.parsed": True,
                        "sections_parsed": parsed_data.get("metadata", {}).get(
                            "sections_parsed", []
                        ),
                        "updated_at": datetime.now(),
                    }
                },
            )

            return True
        except Exception as e:
            print(f"Error saving parsed results: {str(e)}")
            return False

    async def save_ai_results(
        self,
        user_id: str,
        analysis_id: str,
        ai_data: dict,
        malscore: Optional[float] = None,
    ) -> bool:
        """Save AI analysis results"""
        try:
            if not await self._verify_ownership(user_id, analysis_id):
                return False

            document = {
                "analysis_id": analysis_id,
                "results": ai_data.get("results", {}),
                "sections_analyzed": ai_data.get("sections_analyzed", []),
                "model_usage": ai_data.get("model_usage", {}),
                "duration_seconds": ai_data.get("duration_seconds", 0),
                "timestamp": ai_data.get("timestamp", datetime.now().isoformat()),
                "created_at": datetime.now(),
            }

            await self.ai_collection.insert_one(document)

            update_data = {
                "components.ai_analysis": True,
                "ai_sections_analyzed": ai_data.get("sections_analyzed", []),
                "updated_at": datetime.now(),
            }

            if malscore is not None:
                update_data["malscore"] = malscore

            await self.analyses_collection.update_one(
                {"analysis_id": analysis_id}, {"$set": update_data}
            )

            return True
        except Exception as e:
            print(f"Error saving AI results: {str(e)}")
            return False

    async def update_analysis_status(
        self, user_id: str, analysis_id: str, status: str, **kwargs
    ) -> bool:
        """Update analysis status and additional fields"""
        try:
            if not await self._verify_ownership(user_id, analysis_id):
                return False

            update_data = {"status": status, "updated_at": datetime.now(), **kwargs}

            if status == "complete":
                update_data["completed_at"] = datetime.now()

            await self.analyses_collection.update_one(
                {"analysis_id": analysis_id}, {"$set": update_data}
            )

            return True
        except Exception as e:
            print(f"Error updating analysis status: {str(e)}")
            return False

    # -------------------------------------------------------------------------
    # Read Operations
    # -------------------------------------------------------------------------

    async def get_analysis(self, user_id: str, analysis_id: str) -> Optional[dict]:
        """Get analysis record, scoped to user"""
        record = await self.analyses_collection.find_one(
            {"analysis_id": analysis_id, "user_id": ObjectId(user_id)},
            {"_id": 0, "user_id": 0},  # exclude internal fields from response
        )
        return record

    async def get_cape_results(self, user_id: str, analysis_id: str) -> Optional[dict]:
        """Get CAPE results, ownership verified via analyses collection"""
        if not await self._verify_ownership(user_id, analysis_id):
            return None

        return await self.cape_collection.find_one(
            {"analysis_id": analysis_id}, {"_id": 0}
        )

    async def get_parsed_results(
        self, user_id: str, analysis_id: str
    ) -> Optional[dict]:
        """Get parsed results, ownership verified via analyses collection"""
        if not await self._verify_ownership(user_id, analysis_id):
            return None

        return await self.parsed_collection.find_one(
            {"analysis_id": analysis_id}, {"_id": 0}
        )

    async def get_ai_results(self, user_id: str, analysis_id: str) -> Optional[dict]:
        """Get AI results, ownership verified via analyses collection"""
        if not await self._verify_ownership(user_id, analysis_id):
            return None

        return await self.ai_collection.find_one(
            {"analysis_id": analysis_id}, {"_id": 0}
        )

    async def get_all_analyses(
        self, user_id: str, limit: int = 100, skip: int = 0
    ) -> list:
        """Get all analyses for a specific user with pagination"""
        cursor = (
            self.analyses_collection.find(
                {"user_id": ObjectId(user_id)},
                {"_id": 0, "user_id": 0},  # exclude internal fields from response
            )
            .sort("created_at", -1)
            .skip(skip)
            .limit(limit)
        )

        return await cursor.to_list(length=limit)

    async def get_complete_analysis(
        self, user_id: str, analysis_id: str
    ) -> Optional[dict]:
        """Get complete analysis with all components"""
        # Single ownership check — sub-fetches skip re-verification
        analysis = await self.get_analysis(user_id, analysis_id)

        if not analysis:
            return None

        result = {
            "analysis": analysis,
            "cape": None,
            "parsed": None,
            "ai_analysis": None,
        }

        components = analysis.get("components", {})

        if components.get("cape"):
            result["cape"] = await self.cape_collection.find_one(
                {"analysis_id": analysis_id}, {"_id": 0}
            )

        if components.get("parsed"):
            result["parsed"] = await self.parsed_collection.find_one(
                {"analysis_id": analysis_id}, {"_id": 0}
            )

        if components.get("ai_analysis"):
            result["ai_analysis"] = await self.ai_collection.find_one(
                {"analysis_id": analysis_id}, {"_id": 0}
            )

        return result

    # -------------------------------------------------------------------------
    # Delete Operations
    # -------------------------------------------------------------------------

    async def delete_analysis(self, user_id: str, analysis_id: str) -> bool:
        """Delete analysis and all related data"""
        try:
            if not await self._verify_ownership(user_id, analysis_id):
                return False

            await self.cape_collection.delete_one({"analysis_id": analysis_id})
            await self.parsed_collection.delete_one({"analysis_id": analysis_id})
            await self.ai_collection.delete_one({"analysis_id": analysis_id})

            result = await self.analyses_collection.delete_one(
                {"analysis_id": analysis_id}
            )

            return result.deleted_count > 0
        except Exception as e:
            print(f"Error deleting analysis: {str(e)}")
            return False

    # -------------------------------------------------------------------------
    # Aggregation Operations
    # -------------------------------------------------------------------------

    async def get_analysis_count(self, user_id: str) -> int:
        """Get total number of analyses for a specific user"""
        return await self.analyses_collection.count_documents(
            {"user_id": ObjectId(user_id)}
        )
