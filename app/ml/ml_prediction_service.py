# ADDED_ML: Optional, lazy-loaded ML prediction service with in-memory caching.
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.ml.feature_extractor import extract_features
from app.services.threat_intel_Integerations.virustotal_service import VirusTotalService

logger = logging.getLogger(__name__)


class MLPredictionService:
    _instance: "MLPredictionService | None" = None
    _instance_lock = threading.Lock()

    # ADDED_ML: Singleton accessor.
    @classmethod
    def get_instance(cls) -> "MLPredictionService":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self.models_dir = Path(__file__).resolve().parent / "models"
        self.binary_model = None
        self.family_model = None
        self.type_model = None
        self.family_encoder = None
        self.type_encoder = None
        self.metadata: dict[str, Any] = {}
        self.models_loaded = False
        self.lock = threading.Lock()
        self.cache: dict[str, dict[str, Any]] = {}
        # Keep cache short so updated threat-intel signals are reflected quickly.
        self.cache_ttl_seconds = 120
        self.vt_service = VirusTotalService()

    def _model_paths(self) -> dict[str, Path]:
        return {
            "binary": self.models_dir / "binary_model.pkl",
            "family": self.models_dir / "family_model.pkl",
            "type": self.models_dir / "type_model.pkl",
            "family_encoder": self.models_dir / "family_label_encoder.pkl",
            "type_encoder": self.models_dir / "type_label_encoder.pkl",
            "metadata": self.models_dir / "training_metadata.pkl",
        }

    def _default_unavailable(self, prediction_time_ms: float = 0.0) -> dict[str, Any]:
        return {
            "ml_available": False,
            "is_malicious": False,
            "confidence": 0.0,
            "malware_family": "unknown",
            "family_confidence": 0.0,
            "malware_type": "unknown",
            "type_confidence": 0.0,
            "top_3_families": [],
            "vt_insights": None,
            "vt_assisted": False,
            "model_used": "Model training in progress - check back in a few minutes",
            "training_samples_count": int(self.metadata.get("training_samples_count", 0)),
            "prediction_time_ms": float(prediction_time_ms),
        }

    def _extract_hash_candidate(self, document: dict[str, Any] | None) -> str | None:
        if not isinstance(document, dict):
            return None

        preferred_paths = [
            ("data", "target", "file", "sha256"),
            ("data", "target", "sha256"),
            ("target", "file", "sha256"),
            ("target", "sha256"),
            ("sha256",),
            ("sha1",),
            ("md5",),
        ]

        for path in preferred_paths:
            current: Any = document
            found = True
            for key in path:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    found = False
                    break
            if found and isinstance(current, str) and current.strip():
                return current.strip().lower()
        return None

    def _build_vt_assist(self, vt_result: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(vt_result, dict) or not vt_result.get("found"):
            return None

        classification = vt_result.get("threat_classification") or {}
        detection_stats = vt_result.get("detection_stats") or {}

        label = classification.get("popular_threat_label")
        threat_name = classification.get("popular_threat_name")
        categories = classification.get("popular_threat_category") or []
        family_labels = classification.get("family_labels") or []

        suggested_type = "unknown"
        if categories:
            # Prefer stronger, specific category when both broad and specific labels exist.
            lowered = [str(cat).strip().lower() for cat in categories if str(cat).strip()]
            if "ransomware" in lowered:
                suggested_type = "ransomware"
            else:
                suggested_type = lowered[0] if lowered else "unknown"
        elif isinstance(label, str) and label:
            suggested_type = label.split(".", 1)[0].lower()

        suggested_family = str(classification.get("specific_family") or "unknown").strip().lower()
        if suggested_family == "unknown" and isinstance(label, str) and label:
            suggested_family = label.split(".", 1)[-1].split("/", 1)[0].strip().lower()
        elif suggested_family == "unknown" and isinstance(threat_name, str) and threat_name:
            suggested_family = threat_name.strip().lower()

        return {
            "popular_threat_label": label,
            "popular_threat_name": threat_name,
            "popular_threat_category": categories,
            "family_labels": family_labels,
            "suggested_family": suggested_family,
            "suggested_type": suggested_type,
            "threat_level": vt_result.get("threat_level", "unknown"),
            "threat_score": detection_stats.get("threat_score", 0),
            "detection_ratio": detection_stats.get("detection_ratio", "0/0"),
            "vt_url": vt_result.get("vt_url"),
        }

    def _extract_vt_family(self, vt_insights: dict[str, Any] | None) -> str:
        if not vt_insights:
            return "unknown"
        family_labels = vt_insights.get("family_labels") or []
        specific_family = str(vt_insights.get("specific_family") or "unknown").strip().lower()
        if specific_family and specific_family != "unknown":
            return specific_family
        for family in family_labels:
            family_text = str(family).strip().lower()
            if family_text:
                return family_text
        suggested_family = str(vt_insights.get("suggested_family") or "unknown").strip().lower()
        return suggested_family or "unknown"

    async def _persist_vt_signal(
        self,
        db: AsyncIOMotorDatabase,
        analysis_id: str,
        user_id: str | None,
        hash_value: str | None,
        vt_insights: dict[str, Any],
        predicted_family: str,
        predicted_type: str,
    ) -> None:
        try:
            payload = {
                "analysis_id": analysis_id,
                "user_id": user_id,
                "hash_value": (hash_value or "").strip().lower() or None,
                "predicted_family": predicted_family,
                "predicted_type": predicted_type,
                "vt_family": self._extract_vt_family(vt_insights),
                "vt_type": str(vt_insights.get("suggested_type") or "unknown").strip().lower(),
                "vt_label": vt_insights.get("popular_threat_label"),
                "vt_categories": vt_insights.get("popular_threat_category") or [],
                "vt_threat_score": int(vt_insights.get("threat_score") or 0),
                "vt_assisted": True,
                "timestamp": datetime.now(timezone.utc),
                "used_for_retraining": False,
            }
            await db["ml_vt_signals"].update_one(
                {"analysis_id": analysis_id},
                {"$set": payload},
                upsert=True,
            )
        except Exception as exc:
            logger.warning("Could not persist VT signal for %s: %s", analysis_id, exc)

    def _cleanup_cache(self) -> None:
        now = datetime.now(timezone.utc)
        expired = []
        for key, value in self.cache.items():
            ts = value.get("ts")
            if not isinstance(ts, datetime):
                expired.append(key)
            elif now - ts > timedelta(seconds=self.cache_ttl_seconds):
                expired.append(key)
        for key in expired:
            self.cache.pop(key, None)

    def _ensure_models_loaded(self) -> bool:
        with self.lock:
            self._cleanup_cache()
            if self.models_loaded:
                return True
            try:
                paths = self._model_paths()
                if not all(paths[k].exists() for k in ("binary", "family", "type")):
                    return False

                self.binary_model = joblib.load(paths["binary"])
                self.family_model = joblib.load(paths["family"])
                self.type_model = joblib.load(paths["type"])
                if paths["family_encoder"].exists():
                    self.family_encoder = joblib.load(paths["family_encoder"])
                if paths["type_encoder"].exists():
                    self.type_encoder = joblib.load(paths["type_encoder"])
                if paths["metadata"].exists():
                    self.metadata = joblib.load(paths["metadata"])
                self.models_loaded = True
                return True
            except Exception as exc:
                logger.error("Failed to load ML models: %s", exc, exc_info=True)
                self.models_loaded = False
                return False

    async def predict_from_analysis_id(
        self,
        analysis_id: str,
        db: AsyncIOMotorDatabase,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        try:
            cache_key = f"{user_id or 'anon'}:{analysis_id}"
            cached = self.cache.get(cache_key)
            if cached and isinstance(cached.get("ts"), datetime):
                age = datetime.now(timezone.utc) - cached["ts"]
                if age.total_seconds() <= self.cache_ttl_seconds:
                    result = dict(cached["result"])
                    result["prediction_time_ms"] = float((time.perf_counter() - start) * 1000.0)
                    return result

            if not self._ensure_models_loaded():
                return self._default_unavailable((time.perf_counter() - start) * 1000.0)

            analyses_filter: dict[str, Any] = {"analysis_id": analysis_id}
            if user_id:
                # user_id in analyses collection is ObjectId in this project; ownership
                # is enforced by caller route, so we avoid additional risky casting here.
                pass

            analysis_doc = await db["analyses"].find_one(analyses_filter)
            if not analysis_doc:
                return self._default_unavailable((time.perf_counter() - start) * 1000.0)

            parsed_doc = await db["parsed_results"].find_one({"analysis_id": analysis_id})
            if not parsed_doc:
                return self._default_unavailable((time.perf_counter() - start) * 1000.0)

            cape_doc = await db["cape_results"].find_one({"analysis_id": analysis_id})

            sections = parsed_doc.get("sections", {}) if isinstance(parsed_doc, dict) else {}
            behavior = sections.get("behavior", {}) if isinstance(sections, dict) else {}
            report_like = {
                "summary": (
                    behavior.get("data", {}).get("summary", {})
                    if isinstance(behavior.get("data", {}), dict)
                    else behavior.get("summary", {})
                )
            }
            features = extract_features(report_like).reshape(1, -1)

            is_malicious = False
            malicious_conf = 0.0
            if self.binary_model is not None:
                try:
                    pred_bin = int(self.binary_model.predict(features)[0])
                    is_malicious = bool(pred_bin == 1)
                    if hasattr(self.binary_model, "predict_proba"):
                        probs = self.binary_model.predict_proba(features)[0]
                        classes = getattr(self.binary_model, "classes_", None)
                        if isinstance(classes, np.ndarray) and len(classes) > 1:
                            malicious_conf = float(np.max(probs))
                except Exception:
                    pass

            family_name = "unknown"
            family_conf = 0.0
            top3: list[dict[str, Any]] = []
            if self.family_model is not None:
                family_pred = self.family_model.predict(features)[0]
                if self.family_encoder is not None:
                    family_name = str(self.family_encoder.inverse_transform([family_pred])[0])
                else:
                    family_name = str(family_pred)
                if hasattr(self.family_model, "predict_proba"):
                    proba = self.family_model.predict_proba(features)[0]
                    family_conf = float(np.max(proba))
                    indices = np.argsort(proba)[::-1][:3]
                    for idx in indices:
                        cls_val = self.family_model.classes_[idx]
                        if self.family_encoder is not None:
                            cls_name = str(self.family_encoder.inverse_transform([cls_val])[0])
                        else:
                            cls_name = str(cls_val)
                        top3.append({"family": cls_name, "confidence": float(proba[idx])})

            type_name = "unknown"
            type_conf = 0.0
            if self.type_model is not None:
                type_pred = self.type_model.predict(features)[0]
                if self.type_encoder is not None:
                    type_name = str(self.type_encoder.inverse_transform([type_pred])[0])
                else:
                    type_name = str(type_pred)
                if hasattr(self.type_model, "predict_proba"):
                    proba_t = self.type_model.predict_proba(features)[0]
                    type_conf = float(np.max(proba_t))

            vt_insights = None
            vt_hash = (
                self._extract_hash_candidate(cape_doc)
                or self._extract_hash_candidate(parsed_doc)
                or self._extract_hash_candidate(analysis_doc)
            )
            vt_threat_score_norm = 0.0  # Normalized VT threat score (0.0-1.0)
            
            if vt_hash:
                try:
                    vt_raw = await self.vt_service.scan_indicator(vt_hash, "hash", include_relationships=False)
                    vt_insights = self._build_vt_assist(vt_raw)
                    if vt_insights:
                        vt_threat_score = float(vt_insights.get("threat_score") or 0)  # 0-100
                        vt_threat_score_norm = min(max(vt_threat_score / 100.0, 0.0), 1.0)  # Normalize to 0-1
                        
                        vt_family = str(vt_insights.get("suggested_family") or "unknown").strip().lower()
                        vt_type = str(vt_insights.get("suggested_type") or "unknown").strip().lower()
                        vt_categories = [str(v).strip().lower() for v in (vt_insights.get("popular_threat_category") or []) if str(v).strip()]
                        vt_family_labels = [str(v).strip().lower() for v in (vt_insights.get("family_labels") or []) if str(v).strip()]
                        
                        generic_families = {"unknown", "malware", "trojan", "ransomware", "backdoor", "loader", "dropper"}
                        model_family_is_generic = family_name in generic_families
                        model_type_is_generic = type_name in {"unknown", "malware", "trojan"}
                        
                        # IMPORTANT: Only override NAMES, never artificially boost confidence here.
                        # Keep model's own confidence estimates pure.
                        if (model_family_is_generic or family_conf < 0.75) and vt_family:
                            family_name = vt_family
                        
                        # Ransomware has special handling due to its criticality.
                        if "ransomware" in vt_categories and type_name != "ransomware" and vt_threat_score >= 80:
                            type_name = "ransomware"
                        elif (model_type_is_generic or type_conf < 0.75) and vt_type:
                            type_name = vt_type

                        await self._persist_vt_signal(
                            db=db,
                            analysis_id=analysis_id,
                            user_id=user_id,
                            hash_value=vt_hash,
                            vt_insights=vt_insights,
                            predicted_family=family_name,
                            predicted_type=type_name,
                        )
                except Exception as exc:
                    logger.warning("VirusTotal assist skipped for %s: %s", analysis_id, exc)

            # ADDED_ML: Use model's own confidence estimates (pure component averaging).
            # VT is only a secondary adjustment signal; never dominant.
            ml_components: list[float] = []
            if malicious_conf > 0.0:
                ml_components.append(float(malicious_conf))
            if family_conf > 0.0:
                ml_components.append(float(family_conf))
            if type_conf > 0.0:
                ml_components.append(float(type_conf))

            ml_base = float(np.mean(ml_components)) if ml_components else 0.5
            blended_conf = ml_base

            # Light VT-based adjustment: don't dominate, only nudge based on agreement/disagreement.
            if vt_insights and vt_threat_score_norm > 0.0:
                vt_family_labels = [str(v).strip().lower() for v in (vt_insights.get("family_labels") or []) if str(v).strip()]
                family_match = family_name in vt_family_labels if vt_family_labels else False
                
                # VT provides light upward/downward nudge based on agreement and threat_score.
                # Strong agreement (VT=high + name matches) → small boost.
                # Strong disagreement (VT=high + name mismatch) → small penalty.
                # Weak signals (VT threat_score low) → minimal adjustment.
                if vt_threat_score_norm >= 0.75:  # VT is confident in threat
                    if family_match:
                        # Agreement at high confidence: light boost (avoid saturation).
                        blended_conf = min(ml_base + 0.04, 0.90)
                    else:
                        # Disagreement at high confidence: light penalty.
                        blended_conf = max(ml_base - 0.06, 0.15)
                elif vt_threat_score_norm <= 0.25:  # VT is confident it's clean
                    # Light penalty to reduce false positives when VT disagrees.
                    if not family_match:
                        blended_conf = max(ml_base - 0.04, 0.15)
                # else: VT is uncertain (0.25-0.75), don't adjust much.

            malicious_conf = float(min(max(blended_conf, 0.15), 0.96))

            total_time_ms = (time.perf_counter() - start) * 1000.0
            result = {
                "ml_available": True,
                "is_malicious": bool(is_malicious),
                "confidence": float(malicious_conf),
                "malware_family": family_name,
                "family_confidence": float(family_conf),
                "malware_type": type_name,
                "type_confidence": float(type_conf),
                "top_3_families": top3,
                "vt_insights": vt_insights,
                "vt_assisted": bool(vt_insights),
                "model_used": "RandomForest(n_estimators=30,max_depth=10)" + (" + VirusTotal assist" if vt_insights else ""),
                "training_samples_count": int(self.metadata.get("training_samples_count", 0)),
                "prediction_time_ms": float(total_time_ms),
            }

            self.cache[cache_key] = {
                "ts": datetime.now(timezone.utc),
                "result": result,
            }
            return result
        except Exception as exc:
            logger.error("predict_from_analysis_id failed: %s", exc, exc_info=True)
            return self._default_unavailable((time.perf_counter() - start) * 1000.0)

    async def health(self) -> dict[str, Any]:
        try:
            loaded = self._ensure_models_loaded()
            return {
                "available": bool(loaded),
                "models_loaded": bool(self.models_loaded),
                "last_trained": self.metadata.get("trained_at"),
                "samples_count": int(self.metadata.get("training_samples_count", 0)),
            }
        except Exception as exc:
            logger.error("ML health check failed: %s", exc, exc_info=True)
            return {
                "available": False,
                "models_loaded": False,
                "last_trained": None,
                "samples_count": 0,
            }
