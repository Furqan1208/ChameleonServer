# ADDED_ML: New non-destructive ML API routes.
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel

from app.database.mongodb import get_database
from app.dependencies.user_dependency import get_current_user
from app.models.user import UserModel
from app.ml.feedback_service import FeedbackService
from app.ml.ml_prediction_service import MLPredictionService
from app.ml.train_model import (
    auto_retrain_async,
    get_model_performance_async,
    incremental_train_async,
    initial_train_from_avast_async,
)

logger = logging.getLogger(__name__)

router = APIRouter()


class FeedbackRequest(BaseModel):
    analysis_id: str
    corrected_family: str
    corrected_type: str


@router.post("/predict/{analysis_id}")
async def predict_ml(
    analysis_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    try:
        predictor = MLPredictionService.get_instance()
        prediction = await predictor.predict_from_analysis_id(
            analysis_id=analysis_id,
            db=db,
            user_id=current_user.id,
        )
        return {"success": True, "data": prediction}
    except Exception as exc:
        logger.error("/predict failed: %s", exc, exc_info=True)
        return {
            "success": False,
            "data": {
                "ml_available": False,
                "is_malicious": False,
                "confidence": 0.0,
                "malware_family": "unknown",
                "family_confidence": 0.0,
                "malware_type": "unknown",
                "type_confidence": 0.0,
                "top_3_families": [],
                "model_used": "Model training in progress - check back in a few minutes",
                "training_samples_count": 0,
                "prediction_time_ms": 0.0,
            },
            "error": str(exc),
        }


# ADDED_ML: GET alias for prediction to support read-style frontend calls.
@router.get("/predict/{analysis_id}")
async def predict_ml_get(
    analysis_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    try:
        predictor = MLPredictionService.get_instance()
        prediction = await predictor.predict_from_analysis_id(
            analysis_id=analysis_id,
            db=db,
            user_id=current_user.id,
        )
        return {"success": True, "data": prediction}
    except Exception as exc:
        logger.error("/predict (GET) failed: %s", exc, exc_info=True)
        return {
            "success": False,
            "data": {
                "ml_available": False,
                "is_malicious": False,
                "confidence": 0.0,
                "malware_family": "unknown",
                "family_confidence": 0.0,
                "malware_type": "unknown",
                "type_confidence": 0.0,
                "top_3_families": [],
                "model_used": "Model training in progress - check back in a few minutes",
                "training_samples_count": 0,
                "prediction_time_ms": 0.0,
            },
            "error": str(exc),
        }


@router.get("/health")
async def ml_health(
    current_user: UserModel = Depends(get_current_user),
):
    try:
        predictor = MLPredictionService.get_instance()
        health = await predictor.health()
        return {"success": True, **health}
    except Exception as exc:
        logger.error("/health failed: %s", exc, exc_info=True)
        return {
            "success": False,
            "available": False,
            "last_trained": None,
            "samples_count": 0,
            "models_loaded": False,
            "error": str(exc),
        }


@router.post("/retrain")
async def ml_retrain(
    current_user: UserModel = Depends(get_current_user),
):
    # ADDED_ML: admin-only trigger based on existing user role field.
    role = (current_user.role or "").strip().lower()
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required for manual retrain")

    try:
        result = await incremental_train_async()
        if not result.get("success"):
            # Fallback to first-time training if models are absent.
            result = await initial_train_from_avast_async(max_samples=5000)
        return {"success": bool(result.get("success")), "data": result.get("data"), "error": result.get("error")}
    except Exception as exc:
        logger.error("/retrain failed: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc)}


@router.get("/stats")
async def ml_stats(
    current_user: UserModel = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    try:
        perf = await get_model_performance_async()
        history = (
            await db["ml_training_history"].find({}).sort("timestamp", -1).to_list(length=100)
        )
        for row in history:
            row["_id"] = str(row.get("_id"))
            ts = row.get("timestamp")
            if hasattr(ts, "isoformat"):
                row["timestamp"] = ts.isoformat()

        return {
            "success": True,
            "performance": perf.get("data", {}),
            "history": history,
        }
    except Exception as exc:
        logger.error("/stats failed: %s", exc, exc_info=True)
        return {"success": False, "performance": {}, "history": [], "error": str(exc)}


@router.post("/feedback")
async def ml_feedback(
    payload: FeedbackRequest,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    try:
        predictor = MLPredictionService.get_instance()
        pred = await predictor.predict_from_analysis_id(payload.analysis_id, db, user_id=current_user.id)

        service = FeedbackService(db)
        result = await service.store_feedback(
            analysis_id=payload.analysis_id,
            user_id=str(current_user.id),
            corrected_family=payload.corrected_family,
            corrected_type=payload.corrected_type,
            predicted_family=pred.get("malware_family"),
            predicted_type=pred.get("malware_type"),
            vt_insights=pred.get("vt_insights"),
            vt_assisted=pred.get("vt_assisted"),
        )
        return {"success": bool(result.get("success")), "data": result.get("data"), "error": result.get("error")}
    except Exception as exc:
        logger.error("/feedback failed: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc)}


@router.get("/feedback/stats")
async def ml_feedback_stats(
    current_user: UserModel = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    try:
        service = FeedbackService(db)
        accuracy = await service.calculate_feedback_accuracy()

        total_today = await db["ml_feedback"].count_documents(
            {"timestamp": {"$gte": datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)}}
        )

        return {
            "success": True,
            "data": {
                **accuracy,
                "feedback_today": int(total_today),
            },
        }
    except Exception as exc:
        logger.error("/feedback/stats failed: %s", exc, exc_info=True)
        return {"success": False, "data": {}, "error": str(exc)}


@router.post("/auto-retrain")
async def ml_auto_retrain(
    current_user: UserModel = Depends(get_current_user),
):
    # ADDED_ML: Optional helper endpoint to run threshold-guarded retraining.
    role = (current_user.role or "").strip().lower()
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    result = await auto_retrain_async()
    return {"success": bool(result.get("success")), "data": result.get("data"), "error": result.get("error")}
