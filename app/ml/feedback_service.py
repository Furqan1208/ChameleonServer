# ADDED_ML: Feedback collection for correction-driven continuous learning.
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)


class FeedbackService:
    # ADDED_ML: Feedback data is isolated in ml_feedback collection.
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db["ml_feedback"]

    async def store_feedback(
        self,
        analysis_id: str,
        user_id: str,
        corrected_family: str,
        corrected_type: str,
        predicted_family: str | None = None,
        predicted_type: str | None = None,
        vt_insights: dict[str, Any] | None = None,
        vt_assisted: bool | None = None,
    ) -> dict[str, Any]:
        try:
            vt_insights = vt_insights if isinstance(vt_insights, dict) else None
            doc = {
                "analysis_id": analysis_id,
                "user_id": user_id,
                "corrected_family": (corrected_family or "unknown").strip().lower(),
                "corrected_type": (corrected_type or "unknown").strip().lower(),
                "predicted_family": (predicted_family or "unknown").strip().lower(),
                "predicted_type": (predicted_type or "unknown").strip().lower(),
                "vt_assisted": bool(vt_assisted),
                "vt_insights": vt_insights,
                "timestamp": datetime.now(timezone.utc),
                "used_for_retraining": False,
            }
            insert_result = await self.collection.insert_one(doc)
            return {
                "success": True,
                "data": {
                    "feedback_id": str(insert_result.inserted_id),
                    "analysis_id": doc["analysis_id"],
                    "user_id": doc["user_id"],
                    "corrected_family": doc["corrected_family"],
                    "corrected_type": doc["corrected_type"],
                    "predicted_family": doc["predicted_family"],
                    "predicted_type": doc["predicted_type"],
                    "timestamp": doc["timestamp"].isoformat(),
                    "used_for_retraining": doc["used_for_retraining"],
                },
            }
        except Exception as exc:
            logger.error("store_feedback failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def get_feedback_for_retraining(self, since_date: datetime) -> list[dict[str, Any]]:
        try:
            cursor = self.collection.find(
                {
                    "timestamp": {"$gte": since_date},
                    "used_for_retraining": {"$ne": True},
                }
            ).sort("timestamp", 1)
            return await cursor.to_list(length=500)
        except Exception as exc:
            logger.error("get_feedback_for_retraining failed: %s", exc, exc_info=True)
            return []

    async def mark_feedback_used(self, analysis_ids: list[str]) -> None:
        if not analysis_ids:
            return
        try:
            await self.collection.update_many(
                {"analysis_id": {"$in": analysis_ids}},
                {"$set": {"used_for_retraining": True}},
            )
        except Exception as exc:
            logger.warning("mark_feedback_used failed: %s", exc)

    async def calculate_feedback_accuracy(self) -> dict[str, Any]:
        try:
            total = await self.collection.count_documents({})
            if total == 0:
                return {
                    "total_feedback": 0,
                    "family_accuracy": 0.0,
                    "type_accuracy": 0.0,
                    "overall_accuracy": 0.0,
                }

            pipeline = [
                {
                    "$project": {
                        "family_ok": {"$eq": ["$corrected_family", "$predicted_family"]},
                        "type_ok": {"$eq": ["$corrected_type", "$predicted_type"]},
                    }
                },
                {
                    "$group": {
                        "_id": None,
                        "family_ok": {"$sum": {"$cond": ["$family_ok", 1, 0]}},
                        "type_ok": {"$sum": {"$cond": ["$type_ok", 1, 0]}},
                        "total": {"$sum": 1},
                    }
                },
            ]
            data = await self.collection.aggregate(pipeline).to_list(length=1)
            if data:
                family_match = int(data[0].get("family_ok", 0))
                type_match = int(data[0].get("type_ok", 0))
                total = int(data[0].get("total", total))
            else:
                family_match = 0
                type_match = 0

            family_acc = float(family_match / total)
            type_acc = float(type_match / total)
            return {
                "total_feedback": int(total),
                "family_accuracy": family_acc,
                "type_accuracy": type_acc,
                "overall_accuracy": float((family_acc + type_acc) / 2.0),
            }
        except Exception as exc:
            logger.error("calculate_feedback_accuracy failed: %s", exc, exc_info=True)
            return {
                "total_feedback": 0,
                "family_accuracy": 0.0,
                "type_accuracy": 0.0,
                "overall_accuracy": 0.0,
            }
