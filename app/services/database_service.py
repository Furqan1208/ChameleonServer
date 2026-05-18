# D:\FYP\ChameleonServer\app\services\database_service.py
from datetime import datetime
from typing import Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.utils.logger import get_logger

_logger = get_logger("app.services.database")


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
        """Save CAPE analysis results. Stores metadata in MongoDB and full report in file system."""
        try:
            if not await self._verify_ownership(user_id, analysis_id):
                return False

            # Extract lightweight metadata only (full CAPE data stored in file system)
            # This avoids BSON size limit (16MB) exceeded by large CAPE reports
            document = {
                "analysis_id": analysis_id,
                "has_cape": True,
                "target_name": cape_data.get("info", {}).get("name", "unknown"),
                "target_type": cape_data.get("info", {}).get("type", "unknown"),
                "malscore": cape_data.get("info", {}).get("score", 0),
                "signatures_count": len(cape_data.get("signatures", [])),
                "processes_count": len(cape_data.get("behavior", {}).get("processes", [])),
                "created_at": datetime.now(),
            }

            try:
                await self.cape_collection.insert_one(document)
            except Exception as e:
                # Even if MongoDB save fails, still mark cape as available 
                # (full report is saved in file system)
                _logger.warning("Failed to save CAPE metadata to MongoDB: %s. Report available in file system.", str(e))

            # Always mark CAPE component as available (file system backup ensures it exists)
            await self.analyses_collection.update_one(
                {"analysis_id": analysis_id},
                {"$set": {"components.cape": True, "updated_at": datetime.now()}},
            )

            return True
        except Exception as e:
            _logger.exception("Error saving CAPE results: %s", str(e))
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
            _logger.exception("Error saving parsed results: %s", str(e))
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
            _logger.exception("Error saving AI results: %s", str(e))
            return False

    # ✅ NEW METHOD: Save threat intelligence results
    async def save_threat_intel(
        self,
        user_id: str,
        analysis_id: str,
        threat_intel_data: dict,
    ) -> bool:
        """Save threat intelligence results to the analysis record"""
        try:
            if not await self._verify_ownership(user_id, analysis_id):
                return False

            # Store threat intel in a dedicated collection
            ti_collection = self.db["threat_intel_results"]
            
            document = {
                "analysis_id": analysis_id,
                "user_id": ObjectId(user_id),
                "results": threat_intel_data.get("results", {}),
                "summary": threat_intel_data.get("summary", {}),
                "input": threat_intel_data.get("input", ""),
                "input_type": threat_intel_data.get("input_type", ""),
                "timestamp": threat_intel_data.get("timestamp", datetime.utcnow().isoformat()),
                "created_at": datetime.now(),
            }

            await ti_collection.insert_one(document)

            # Update the main analysis record to mark threat intel as available
            await self.analyses_collection.update_one(
                {"analysis_id": analysis_id},
                {
                    "$set": {
                        "components.threat_intel": True,
                        "updated_at": datetime.now(),
                    }
                },
            )

            _logger.info("Threat intel saved for analysis %s", analysis_id)
            return True
        except Exception as e:
            _logger.exception("Error saving threat intel: %s", str(e))
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
            _logger.exception("Error updating analysis status: %s", str(e))
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

    # ✅ NEW METHOD: Get threat intel results
    async def get_threat_intel(
        self, user_id: str, analysis_id: str
    ) -> Optional[dict]:
        """Get threat intelligence results, ownership verified via analyses collection"""
        if not await self._verify_ownership(user_id, analysis_id):
            return None

        ti_collection = self.db["threat_intel_results"]
        return await ti_collection.find_one(
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

        analyses = await cursor.to_list(length=limit)

        # Backfill missing malscore from file system parsed output when available.
        # This handles older analyses produced before malscore was stored in DB.
        from app.services.report_structure_service import report_structure_service

        for a in analyses:
            try:
                if not a.get("malscore"):
                    analysis_id = a.get("analysis_id")
                    if not analysis_id:
                        continue

                    parsed_file = (
                        report_structure_service.base_dir / analysis_id / "parsed" / "combined.json"
                    )
                    if parsed_file.exists():
                        try:
                            combined = report_structure_service.load_json(parsed_file)
                            malscore = (
                                combined.get("sections", {})
                                .get("signatures", {})
                                .get("malscore")
                            )
                            if malscore is not None:
                                a["malscore"] = malscore
                                # Persist back to DB for future calls
                                try:
                                    await self.analyses_collection.update_one(
                                        {"analysis_id": analysis_id},
                                        {"$set": {"malscore": malscore}},
                                    )
                                except Exception:
                                    # Best-effort write; ignore failures
                                    pass
                        except Exception:
                            # ignore parse/read errors and continue
                            pass
            except Exception:
                # Protect listing from any unexpected exception per-item
                continue

        return analyses

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
            "threat_intel": None,  # ✅ Added threat_intel
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

        # ✅ Fetch threat intel if available
        if components.get("threat_intel"):
            ti_collection = self.db["threat_intel_results"]
            result["threat_intel"] = await ti_collection.find_one(
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
            
            # ✅ Also delete threat intel
            ti_collection = self.db["threat_intel_results"]
            await ti_collection.delete_one({"analysis_id": analysis_id})

            result = await self.analyses_collection.delete_one(
                {"analysis_id": analysis_id}
            )

            return result.deleted_count > 0
        except Exception as e:
            _logger.exception("Error deleting analysis: %s", str(e))
            return False

    # -------------------------------------------------------------------------
    # Aggregation Operations
    # -------------------------------------------------------------------------

    async def get_analysis_count(self, user_id: str) -> int:
        """Get total number of analyses for a specific user"""
        return await self.analyses_collection.count_documents(
            {"user_id": ObjectId(user_id)}
        )