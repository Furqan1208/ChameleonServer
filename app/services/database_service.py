# D:\FYP\ChameleonServer\app\services\database_service.py
from datetime import datetime
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase


class DatabaseService:
    """Service for managing analysis data in MongoDB"""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.cape_collection = db["cape_results"]
        self.parsed_collection = db["parsed_results"]
        self.ai_collection = db["ai_results"]
        self.analyses_collection = db["analyses"]

    async def create_analysis_record(
        self,
        analysis_id: str,
        filename: str,
        analysis_type: str,
        model_name: Optional[str] = None,
    ) -> dict:
        """Create initial analysis record"""
        record = {
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

    async def save_cape_results(self, analysis_id: str, cape_data: dict) -> bool:
        """Save CAPE analysis results"""
        try:
            document = {
                "analysis_id": analysis_id,
                "data": cape_data,
                "created_at": datetime.now(),
            }

            await self.cape_collection.insert_one(document)

            # Update analysis record
            await self.analyses_collection.update_one(
                {"analysis_id": analysis_id},
                {"$set": {"components.cape": True, "updated_at": datetime.now()}},
            )

            return True
        except Exception as e:
            print(f"Error saving CAPE results: {str(e)}")
            return False

    async def save_parsed_results(self, analysis_id: str, parsed_data: dict) -> bool:
        """Save parsed results"""
        try:
            document = {
                "analysis_id": analysis_id,
                "metadata": parsed_data.get("metadata", {}),
                "sections": parsed_data.get("sections", {}),
                "created_at": datetime.now(),
            }

            await self.parsed_collection.insert_one(document)

            # Update analysis record
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
        self, analysis_id: str, ai_data: dict, malscore: Optional[float] = None
    ) -> bool:
        """Save AI analysis results"""
        try:
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

            # Update analysis record
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
        self, analysis_id: str, status: str, **kwargs
    ) -> bool:
        """Update analysis status and additional fields"""
        try:
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

    async def get_analysis(self, analysis_id: str) -> Optional[dict]:
        """Get analysis record"""
        record = await self.analyses_collection.find_one(
            {"analysis_id": analysis_id}, {"_id": 0}
        )
        return record

    async def get_cape_results(self, analysis_id: str) -> Optional[dict]:
        """Get CAPE results"""
        result = await self.cape_collection.find_one(
            {"analysis_id": analysis_id}, {"_id": 0}
        )
        return result

    async def get_parsed_results(self, analysis_id: str) -> Optional[dict]:
        """Get parsed results"""
        result = await self.parsed_collection.find_one(
            {"analysis_id": analysis_id}, {"_id": 0}
        )
        return result

    async def get_ai_results(self, analysis_id: str) -> Optional[dict]:
        """Get AI results"""
        result = await self.ai_collection.find_one(
            {"analysis_id": analysis_id}, {"_id": 0}
        )
        return result

    async def get_all_analyses(self, limit: int = 100, skip: int = 0) -> list:
        """Get all analyses with pagination"""
        cursor = (
            self.analyses_collection.find({}, {"_id": 0})
            .sort("created_at", -1)
            .skip(skip)
            .limit(limit)
        )

        analyses = await cursor.to_list(length=limit)
        return analyses

    async def get_complete_analysis(self, analysis_id: str) -> Optional[dict]:
        """Get complete analysis with all components"""
        analysis = await self.get_analysis(analysis_id)

        if not analysis:
            return None

        result = {
            "analysis": analysis,
            "cape": None,
            "parsed": None,
            "ai_analysis": None,
        }

        if analysis.get("components", {}).get("cape"):
            result["cape"] = await self.get_cape_results(analysis_id)

        if analysis.get("components", {}).get("parsed"):
            result["parsed"] = await self.get_parsed_results(analysis_id)

        if analysis.get("components", {}).get("ai_analysis"):
            result["ai_analysis"] = await self.get_ai_results(analysis_id)

        return result

    async def delete_analysis(self, analysis_id: str) -> bool:
        """Delete analysis and all related data"""
        try:
            # Delete from all collections
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

    async def get_analysis_count(self) -> int:
        """Get total number of analyses"""
        return await self.analyses_collection.count_documents({})
