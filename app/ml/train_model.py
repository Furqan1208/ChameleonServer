# ADDED_ML: Training pipeline with memory-constrained initial and incremental learning.
from __future__ import annotations

import asyncio
import gc
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder

from app.ml.avast_dataset_loader import AvastDatasetLoader
from app.ml.feature_extractor import get_feature_count

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parent / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
TRAINING_DATA_PATH = MODELS_DIR / "training_dataset.csv"
INCREMENTAL_LABELS_PATH = Path(__file__).resolve().parents[2] / "dataset" / "public_labels_incremental.csv"

ALLOWED_TYPES = [
    "banker",
    "trojan",
    "pws",
    "coinminer",
    "rat",
    "keylogger",
    "ransomware",
    "malware",
    "loader",
    "dropper",
    "backdoor",
    "worm",
    "spyware",
    "adware",
    "botnet",
    "stealer",
    "cryptor",
    "other",
]


# ADDED_ML: DB helper for scripts and scheduler usage.
async def _get_db() -> tuple[AsyncIOMotorClient, AsyncIOMotorDatabase]:
    mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    db_name = os.getenv("DB_NAME", "app_database")
    client = AsyncIOMotorClient(mongo_uri)
    return client, client[db_name]


def _normalize_type(raw: str) -> str:
    text = (raw or "unknown").strip().lower()
    if text in ALLOWED_TYPES:
        return text

    # ADDED_ML: Keyword mapping for broader generic categories and emerging labels.
    keyword_map = {
        "ransom": "ransomware",
        "encrypt": "ransomware",
        "locker": "ransomware",
        "bank": "banker",
        "credential": "pws",
        "password": "pws",
        "miner": "coinminer",
        "rat": "rat",
        "remote": "rat",
        "keylog": "keylogger",
        "load": "loader",
        "drop": "dropper",
        "backdoor": "backdoor",
        "worm": "worm",
        "spy": "spyware",
        "adware": "adware",
        "bot": "botnet",
        "steal": "stealer",
        "crypt": "cryptor",
        "trojan": "trojan",
        "malware": "malware",
    }
    for key, normalized in keyword_map.items():
        if key in text:
            return normalized

    for known in ALLOWED_TYPES:
        if known in text:
            return known
    return "other"


def _fit_rf_classifier(x: np.ndarray, y: np.ndarray) -> RandomForestClassifier:
    # ADDED_ML: Fixed memory-safe params requested by user.
    model = RandomForestClassifier(
        n_estimators=30,
        max_depth=10,
        n_jobs=1,
        random_state=42,
    )
    model.fit(x, y)
    return model


def _save_models(
    binary_model: Any,
    family_model: Any,
    type_model: Any,
    family_encoder: LabelEncoder,
    type_encoder: LabelEncoder,
    metadata: dict[str, Any],
) -> None:
    joblib.dump(binary_model, MODELS_DIR / "binary_model.pkl", compress=3)
    joblib.dump(family_model, MODELS_DIR / "family_model.pkl", compress=3)
    joblib.dump(type_model, MODELS_DIR / "type_model.pkl", compress=3)
    joblib.dump(family_encoder, MODELS_DIR / "family_label_encoder.pkl", compress=3)
    joblib.dump(type_encoder, MODELS_DIR / "type_label_encoder.pkl", compress=3)
    joblib.dump(metadata, MODELS_DIR / "training_metadata.pkl", compress=3)


async def _upsert_trained_samples(
    db: AsyncIOMotorDatabase,
    source: str,
    sample_ids: list[str],
) -> None:
    if not sample_ids:
        return

    docs = []
    now = datetime.now(timezone.utc)
    for sample_id in sample_ids:
        docs.append(
            {
                "source": source,
                "sample_id": sample_id,
                "sample_key": f"{source}:{sample_id}",
                "trained_at": now,
            }
        )

    collection = db["ml_trained_samples"]
    for doc in docs:
        await collection.update_one(
            {"sample_key": doc["sample_key"]},
            {"$set": doc},
            upsert=True,
        )


async def _write_training_history(db: AsyncIOMotorDatabase, payload: dict[str, Any]) -> None:
    try:
        await db["ml_training_history"].insert_one(payload)
    except Exception as exc:
        logger.warning("Could not write ml_training_history: %s", exc)


async def _load_feedback_label_map(db: AsyncIOMotorDatabase) -> dict[str, dict[str, str]]:
    data: dict[str, dict[str, str]] = {}
    try:
        cursor = db["ml_feedback"].find({}).sort("timestamp", -1)
        rows = await cursor.to_list(length=10000)
        for row in rows:
            analysis_id = row.get("analysis_id")
            if not analysis_id or analysis_id in data:
                continue
            data[analysis_id] = {
                "family": str(row.get("corrected_family", "unknown") or "unknown").lower(),
                "type": _normalize_type(str(row.get("corrected_type", "unknown") or "unknown")),
            }
        vt_cursor = db["ml_vt_signals"].find({}).sort("timestamp", -1)
        vt_rows = await vt_cursor.to_list(length=10000)
        for row in vt_rows:
            analysis_id = row.get("analysis_id")
            if not analysis_id or analysis_id in data:
                continue
            vt_family = str(row.get("vt_family", "unknown") or "unknown").lower()
            vt_type = _normalize_type(str(row.get("vt_type", "unknown") or "unknown"))
            data[analysis_id] = {
                "family": vt_family,
                "type": vt_type,
            }

        # ADDED_ML: Keep a local incremental label dataset (non-destructive to official public_labels.csv).
        export_rows: list[dict[str, Any]] = []
        seen_export: set[str] = set()

        for row in rows:
            analysis_id = str(row.get("analysis_id") or "").strip()
            if not analysis_id or analysis_id in seen_export:
                continue
            seen_export.add(analysis_id)
            export_rows.append(
                {
                    "sample_id": analysis_id,
                    "analysis_id": analysis_id,
                    "sha256": None,
                    "classification_family": str(row.get("corrected_family", "unknown") or "unknown").lower(),
                    "classification_type": _normalize_type(str(row.get("corrected_type", "unknown") or "unknown")),
                    "label_source": "user_feedback",
                    "updated_at": row.get("timestamp"),
                }
            )

        for row in vt_rows:
            analysis_id = str(row.get("analysis_id") or "").strip()
            if not analysis_id or analysis_id in seen_export:
                continue
            seen_export.add(analysis_id)
            export_rows.append(
                {
                    "sample_id": analysis_id,
                    "analysis_id": analysis_id,
                    "sha256": row.get("hash_value"),
                    "classification_family": str(row.get("vt_family", "unknown") or "unknown").lower(),
                    "classification_type": _normalize_type(str(row.get("vt_type", "unknown") or "unknown")),
                    "label_source": "virustotal_assist",
                    "updated_at": row.get("timestamp"),
                }
            )

        if export_rows:
            export_df = pd.DataFrame(export_rows)
            INCREMENTAL_LABELS_PATH.parent.mkdir(parents=True, exist_ok=True)
            export_df.to_csv(INCREMENTAL_LABELS_PATH, index=False)
    except Exception as exc:
        logger.warning("Could not load feedback labels: %s", exc)
    return data


def _build_behavior_report_like(parsed_doc: dict[str, Any]) -> dict[str, Any]:
    sections = parsed_doc.get("sections", {}) if isinstance(parsed_doc, dict) else {}
    behavior = sections.get("behavior", {}) if isinstance(sections, dict) else {}
    if isinstance(behavior.get("data"), dict):
        summary = behavior.get("data", {}).get("summary", {})
    else:
        summary = behavior.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    return {"summary": summary}


async def _fetch_new_analysis_samples(
    db: AsyncIOMotorDatabase,
    limit: int = 100,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, list[str]]:
    from app.ml.feature_extractor import extract_features

    trained_analysis_ids = set(
        await db["ml_trained_samples"].distinct("sample_id", {"source": "analysis"})
    )
    feedback_map = await _load_feedback_label_map(db)

    x_rows: list[np.ndarray] = []
    y_binary: list[int] = []
    y_family: list[str] = []
    y_type: list[str] = []
    ids: list[str] = []

    cursor = db["analyses"].find({}).sort("created_at", -1)
    docs = await cursor.to_list(length=2000)

    for analysis in docs:
        if len(ids) >= limit:
            break
        analysis_id = str(analysis.get("analysis_id", "")).strip()
        if not analysis_id or analysis_id in trained_analysis_ids:
            continue

        parsed_doc = await db["parsed_results"].find_one({"analysis_id": analysis_id})
        if not parsed_doc:
            continue

        features = extract_features(_build_behavior_report_like(parsed_doc))
        x_rows.append(features)

        malscore = float(analysis.get("malscore", 0.0) or 0.0)
        y_binary.append(1 if malscore >= 1.0 else 0)

        feedback_label = feedback_map.get(analysis_id)
        if feedback_label:
            y_family.append(feedback_label["family"])
            y_type.append(feedback_label["type"])
        else:
            y_family.append("unknown")
            y_type.append("unknown")

        ids.append(analysis_id)

    if not x_rows:
        return (
            np.empty((0, get_feature_count()), dtype=np.float32),
            np.empty((0,), dtype=np.int32),
            np.empty((0,), dtype=object),
            [],
        )

    return (
        np.vstack(x_rows).astype(np.float32, copy=False),
        np.asarray(y_binary, dtype=np.int32),
        np.asarray([f"{fam}||{typ}" for fam, typ in zip(y_family, y_type)], dtype=object),
        ids,
    )


def _split_family_type(combined: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    families: list[str] = []
    types: list[str] = []
    for item in combined.tolist():
        text = str(item)
        if "||" in text:
            fam, typ = text.split("||", 1)
        else:
            fam, typ = text, "unknown"
        families.append((fam or "unknown").lower())
        types.append(_normalize_type(typ))
    return np.asarray(families, dtype=object), np.asarray(types, dtype=object)


def _save_training_dataset(x: np.ndarray, y_binary: np.ndarray, y_family: np.ndarray, y_type: np.ndarray) -> None:
    cols = {f"f_{i}": x[:, i] for i in range(x.shape[1])}
    cols["binary"] = y_binary
    cols["family"] = y_family
    cols["mtype"] = y_type
    df = pd.DataFrame(cols)
    df.to_csv(TRAINING_DATA_PATH, index=False)


def _load_training_dataset() -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    if not TRAINING_DATA_PATH.exists():
        return (
            np.empty((0, get_feature_count()), dtype=np.float32),
            np.empty((0,), dtype=np.int32),
            np.empty((0,), dtype=object),
            np.empty((0,), dtype=object),
        )

    df = pd.read_csv(TRAINING_DATA_PATH, low_memory=True)
    feature_cols = [c for c in df.columns if c.startswith("f_")]
    feature_cols = sorted(feature_cols, key=lambda n: int(n.split("_")[1]))
    x = df[feature_cols].astype(np.float32).to_numpy(copy=False)
    y_binary = df["binary"].astype(np.int32).to_numpy(copy=False)
    y_family = df["family"].astype(str).to_numpy(copy=False)
    y_type = df["mtype"].astype(str).to_numpy(copy=False)
    return x, y_binary, y_family, y_type


def _train_models(
    x: np.ndarray,
    y_binary: np.ndarray,
    y_family: np.ndarray,
    y_type: np.ndarray,
) -> tuple[dict[str, Any], Any, Any, Any, LabelEncoder, LabelEncoder]:
    # ADDED_ML: Train binary/family/type models separately per memory rule.
    binary_model = _fit_rf_classifier(x, y_binary)

    fam_encoder = LabelEncoder()
    fam_encoded = fam_encoder.fit_transform(y_family)
    family_model = _fit_rf_classifier(x, fam_encoded)

    type_encoder = LabelEncoder()
    type_encoded = type_encoder.fit_transform(y_type)
    type_model = _fit_rf_classifier(x, type_encoded)

    # ADDED_ML: In-sample metrics are used for lightweight monitoring.
    perf = {
        "binary_accuracy": float(accuracy_score(y_binary, binary_model.predict(x))),
        "family_accuracy": float(accuracy_score(fam_encoded, family_model.predict(x))),
        "type_accuracy": float(accuracy_score(type_encoded, type_model.predict(x))),
    }
    return perf, binary_model, family_model, type_model, fam_encoder, type_encoder


async def _train_from_avast_async(
    max_samples: int,
    source_label: str,
    mode_label: str,
    enforce_initial_cap: bool,
) -> dict[str, Any]:
    client = None
    try:
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        client, db = await _get_db()

        effective_max = int(max_samples)
        if enforce_initial_cap:
            effective_max = min(effective_max, 5000)

        loader = AvastDatasetLoader()
        x_batches: list[np.ndarray] = []
        y_family_batches: list[np.ndarray] = []
        y_type_batches: list[np.ndarray] = []
        avast_sample_ids: list[str] = []
        loaded = 0

        for x_batch, family_labels, type_labels, shas in loader.load_samples_batch(
            batch_size=500,
            start_index=0,
            max_samples=effective_max,
        ):
            if x_batch.size == 0:
                continue

            remaining = max(0, effective_max - loaded)
            if remaining <= 0:
                break

            if x_batch.shape[0] > remaining:
                x_batch = x_batch[:remaining]
                family_labels = family_labels[:remaining]
                type_labels = type_labels[:remaining]
                shas = shas[:remaining]

            x_batches.append(x_batch.astype(np.float32, copy=False))
            y_family_batches.append(np.asarray([str(v or "unknown").lower() for v in family_labels], dtype=object))
            y_type_batches.append(np.asarray([_normalize_type(str(v)) for v in type_labels], dtype=object))
            avast_sample_ids.extend(shas)

            loaded += x_batch.shape[0]
            gc.collect()

            if loaded >= effective_max:
                break

        if not x_batches:
            return {
                "success": False,
                "ml_available": False,
                "error": "No Avast samples could be loaded for training.",
            }

        x = np.vstack(x_batches).astype(np.float32, copy=False)
        y_family = np.concatenate(y_family_batches)
        y_type = np.concatenate(y_type_batches)
        y_binary = np.ones((x.shape[0],), dtype=np.int32)

        # Keep top-10 families + unknown to control memory/class cardinality.
        family_counts = pd.Series(y_family).value_counts()
        top_10 = set(family_counts.head(10).index.tolist())
        y_family = np.asarray([f if f in top_10 else "unknown" for f in y_family], dtype=object)

        perf, binary_model, family_model, type_model, fam_encoder, type_encoder = _train_models(
            x=x,
            y_binary=y_binary,
            y_family=y_family,
            y_type=y_type,
        )

        metadata = {
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_samples_count": int(x.shape[0]),
            "source": source_label,
            **perf,
        }
        _save_models(binary_model, family_model, type_model, fam_encoder, type_encoder, metadata)
        _save_training_dataset(x, y_binary, y_family, y_type)

        await _upsert_trained_samples(db, source="avast", sample_ids=avast_sample_ids)
        await _write_training_history(
            db,
            {
                "timestamp": datetime.now(timezone.utc),
                "mode": mode_label,
                "source": "avast",
                "training_samples_count": int(x.shape[0]),
                **perf,
            },
        )

        gc.collect()
        return {
            "success": True,
            "data": {
                "training_samples_count": int(x.shape[0]),
                **perf,
            },
        }
    except MemoryError as exc:
        logger.error("Out of memory during Avast training: %s", exc)
        gc.collect()
        return {
            "success": False,
            "ml_available": False,
            "error": "Insufficient memory",
        }
    except Exception as exc:
        logger.error("Avast training failed: %s", exc, exc_info=True)
        return {
            "success": False,
            "ml_available": False,
            "error": str(exc),
        }
    finally:
        if client is not None:
            client.close()


async def initial_train_from_avast_async(max_samples: int = 5000) -> dict[str, Any]:
    # ADDED_ML: Keeps existing memory-safe initial cap at 5000 for first-time setup.
    return await _train_from_avast_async(
        max_samples=max_samples,
        source_label="avast_initial",
        mode_label="initial",
        enforce_initial_cap=True,
    )


async def full_train_from_avast_async(max_samples: int | None = None) -> dict[str, Any]:
    # ADDED_ML: Explicit full-dataset training path (still 500-sample batch processing).
    effective_max = max_samples
    if effective_max is None:
        loader = AvastDatasetLoader()
        effective_max = max(loader.get_total_sample_count(), 0)
    return await _train_from_avast_async(
        max_samples=int(effective_max),
        source_label="avast_full",
        mode_label="full",
        enforce_initial_cap=False,
    )


async def incremental_train_async() -> dict[str, Any]:
    client = None
    try:
        client, db = await _get_db()

        x_base, yb_base, yf_base, yt_base = _load_training_dataset()
        if x_base.shape[0] == 0:
            return await initial_train_from_avast_async(max_samples=5000)

        x_new, yb_new, yft_new_combined, new_analysis_ids = await _fetch_new_analysis_samples(db, limit=100)
        if x_new.shape[0] == 0:
            return {
                "success": True,
                "data": {
                    "message": "No new analysis samples available for incremental training.",
                    "new_samples": 0,
                },
            }

        yf_new, yt_new = _split_family_type(yft_new_combined)

        x_all = np.vstack([x_base, x_new]).astype(np.float32, copy=False)
        yb_all = np.concatenate([yb_base, yb_new]).astype(np.int32, copy=False)
        yf_all = np.concatenate([yf_base, yf_new]).astype(object, copy=False)
        yt_all = np.concatenate([yt_base, yt_new]).astype(object, copy=False)

        perf, binary_model, family_model, type_model, fam_encoder, type_encoder = _train_models(
            x=x_all,
            y_binary=yb_all,
            y_family=yf_all,
            y_type=yt_all,
        )

        metadata = {
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_samples_count": int(x_all.shape[0]),
            "source": "incremental",
            **perf,
        }
        _save_models(binary_model, family_model, type_model, fam_encoder, type_encoder, metadata)
        _save_training_dataset(x_all, yb_all, yf_all, yt_all)

        await _upsert_trained_samples(db, source="analysis", sample_ids=new_analysis_ids)
        await _write_training_history(
            db,
            {
                "timestamp": datetime.now(timezone.utc),
                "mode": "incremental",
                "source": "analysis",
                "new_samples": int(x_new.shape[0]),
                "training_samples_count": int(x_all.shape[0]),
                **perf,
            },
        )

        gc.collect()
        return {
            "success": True,
            "data": {
                "new_samples": int(x_new.shape[0]),
                "training_samples_count": int(x_all.shape[0]),
                **perf,
            },
        }
    except MemoryError as exc:
        logger.error("Out of memory during incremental training: %s", exc)
        gc.collect()
        return {
            "success": False,
            "ml_available": False,
            "error": "Insufficient memory",
        }
    except Exception as exc:
        logger.error("incremental_train_async failed: %s", exc, exc_info=True)
        return {
            "success": False,
            "ml_available": False,
            "error": str(exc),
        }
    finally:
        if client is not None:
            client.close()


async def needs_retraining_async() -> bool:
    client = None
    try:
        client, db = await _get_db()
        trained_ids = set(
            await db["ml_trained_samples"].distinct("sample_id", {"source": "analysis"})
        )

        if not trained_ids:
            total_analyses = await db["analyses"].count_documents({})
            return total_analyses >= 30

        # ADDED_ML: Evaluate new analyses from recent window to avoid heavy scans.
        recent = await db["analyses"].find({}, {"analysis_id": 1}).sort("created_at", -1).to_list(length=5000)
        new_count = 0
        for doc in recent:
            analysis_id = str(doc.get("analysis_id", "")).strip()
            if analysis_id and analysis_id not in trained_ids:
                new_count += 1
            if new_count >= 30:
                return True
        return False
    except Exception as exc:
        logger.error("needs_retraining_async failed: %s", exc, exc_info=True)
        return False
    finally:
        if client is not None:
            client.close()


async def auto_retrain_async() -> dict[str, Any]:
    try:
        if not await needs_retraining_async():
            return {
                "success": True,
                "data": {"retrained": False, "message": "Retraining threshold not reached."},
            }
        result = await incremental_train_async()
        return {
            "success": bool(result.get("success")),
            "data": {"retrained": bool(result.get("success")), **(result.get("data") or {})},
            "error": result.get("error"),
        }
    except Exception as exc:
        logger.error("auto_retrain_async failed: %s", exc, exc_info=True)
        return {"success": False, "ml_available": False, "error": str(exc)}


async def get_model_performance_async() -> dict[str, Any]:
    client = None
    try:
        client, db = await _get_db()
        latest = await db["ml_training_history"].find_one({}, sort=[("timestamp", -1)])
        if not latest:
            metadata_path = MODELS_DIR / "training_metadata.pkl"
            if metadata_path.exists():
                try:
                    metadata = joblib.load(metadata_path)
                    return {
                        "success": True,
                        "data": {
                            "source": metadata.get("source", "current_model"),
                            "training_samples_count": int(metadata.get("training_samples_count", 0) or 0),
                            "binary_accuracy": float(metadata.get("binary_accuracy", 0.0) or 0.0),
                            "family_accuracy": float(metadata.get("family_accuracy", 0.0) or 0.0),
                            "type_accuracy": float(metadata.get("type_accuracy", 0.0) or 0.0),
                            "timestamp": metadata.get("trained_at"),
                        },
                    }
                except Exception as exc:
                    logger.warning("Could not read training metadata fallback: %s", exc)
            return {"success": True, "data": {}}
        latest.pop("_id", None)
        return {"success": True, "data": latest}
    except Exception as exc:
        logger.error("get_model_performance_async failed: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc), "data": {}}
    finally:
        if client is not None:
            client.close()


# ADDED_ML: Sync wrappers for CLI usability and simple external calls.
def initial_train_from_avast(max_samples: int = 5000) -> dict[str, Any]:
    return asyncio.run(initial_train_from_avast_async(max_samples=max_samples))


def full_train_from_avast(max_samples: int | None = None) -> dict[str, Any]:
    return asyncio.run(full_train_from_avast_async(max_samples=max_samples))


def incremental_train() -> dict[str, Any]:
    return asyncio.run(incremental_train_async())


def needs_retraining() -> bool:
    return asyncio.run(needs_retraining_async())


def auto_retrain() -> dict[str, Any]:
    return asyncio.run(auto_retrain_async())


def get_model_performance() -> dict[str, Any]:
    return asyncio.run(get_model_performance_async())
