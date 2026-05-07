# ADDED_ML: Memory-efficient Avast dataset loader with 500-sample batching.
import gc
import logging
from pathlib import Path
from typing import Generator

import numpy as np
import pandas as pd
from tqdm import tqdm

from app.ml.feature_extractor import extract_features, get_feature_names
from app.ml.utils import safe_file_read

logger = logging.getLogger(__name__)


class AvastDatasetLoader:
    # ADDED_ML: Loader reads labels lazily and processes JSONs in fixed-size batches.
    def __init__(self, dataset_root: str | Path | None = None):
        root = Path(dataset_root) if dataset_root else Path(__file__).resolve().parents[1] / "dataset"
        self.dataset_root = root
        self.labels_path = root / "public_labels.csv"
        self.reports_dir = root / "public_small_reports"
        self.cache_path = root / "avast_feature_cache.csv"
        self.feature_names = get_feature_names()
        self._labels_df: pd.DataFrame | None = None

    def _load_labels(self) -> pd.DataFrame:
        if self._labels_df is None:
            if not self.labels_path.exists():
                raise FileNotFoundError(f"Labels file not found: {self.labels_path}")
            self._labels_df = pd.read_csv(self.labels_path, low_memory=True)
            required = {"sha256", "classification_family", "classification_type"}
            missing = [c for c in required if c not in self._labels_df.columns]
            if missing:
                raise ValueError(f"Missing required columns in labels CSV: {missing}")
        return self._labels_df

    def get_total_sample_count(self) -> int:
        try:
            labels_df = self._load_labels()
            return int(len(labels_df))
        except Exception as exc:
            logger.error("get_total_sample_count failed: %s", exc, exc_info=True)
            return 0

    def _load_cache_map(self) -> dict[str, pd.Series]:
        if not self.cache_path.exists():
            return {}

        try:
            cache_df = pd.read_csv(self.cache_path, low_memory=True)
            if "sha256" not in cache_df.columns:
                return {}
            cache_df = cache_df.drop_duplicates(subset=["sha256"], keep="last")
            cache_df = cache_df.set_index("sha256")
            return {idx: row for idx, row in cache_df.iterrows()}
        except Exception as exc:
            logger.warning("Could not load Avast cache: %s", exc)
            return {}

    def _append_cache_rows(self, rows: list[dict]) -> None:
        if not rows:
            return
        try:
            df = pd.DataFrame(rows)
            header = not self.cache_path.exists()
            df.to_csv(self.cache_path, mode="a", index=False, header=header)
        except Exception as exc:
            logger.warning("Could not append to Avast cache: %s", exc)

    def load_samples_batch(
        self,
        batch_size: int = 500,
        start_index: int = 0,
        max_samples: int | None = None,
    ) -> Generator[tuple[np.ndarray, list[str], list[str], list[str]], None, None]:
        """
        Yield memory-safe batches: (features, family_labels, type_labels, shas).
        Hard-limits batch_size to 500 to respect 8GB RAM environments.
        """
        try:
            labels_df = self._load_labels()
            cache_map = self._load_cache_map()

            safe_batch_size = max(1, min(int(batch_size), 500))
            end_index = len(labels_df) if max_samples is None else min(len(labels_df), start_index + int(max_samples))

            iterator = range(start_index, end_index, safe_batch_size)
            for batch_start in tqdm(iterator, desc="Avast batches", unit="batch"):
                batch_df = labels_df.iloc[batch_start : min(batch_start + safe_batch_size, end_index)]

                features_list: list[np.ndarray] = []
                family_labels: list[str] = []
                type_labels: list[str] = []
                shas: list[str] = []
                new_cache_rows: list[dict] = []

                for _, row in batch_df.iterrows():
                    sha = str(row.get("sha256", "")).strip().lower()
                    if not sha:
                        continue

                    family = str(row.get("classification_family", "unknown") or "unknown").strip().lower()
                    mtype = str(row.get("classification_type", "unknown") or "unknown").strip().lower()

                    cached_row = cache_map.get(sha)
                    if cached_row is not None:
                        try:
                            feature_values = [float(cached_row.get(name, 0.0)) for name in self.feature_names]
                            feature_vec = np.asarray(feature_values, dtype=np.float32)
                        except Exception:
                            feature_vec = np.zeros(len(self.feature_names), dtype=np.float32)
                    else:
                        report_path = self.reports_dir / f"{sha}.json"
                        report = safe_file_read(report_path)
                        if report is None:
                            logger.debug("Missing or unreadable Avast report: %s", report_path)
                            continue

                        feature_vec = extract_features(report)
                        cache_row = {
                            "sha256": sha,
                            "classification_family": family,
                            "classification_type": mtype,
                        }
                        for idx, name in enumerate(self.feature_names):
                            cache_row[name] = float(feature_vec[idx])
                        new_cache_rows.append(cache_row)

                    features_list.append(feature_vec)
                    family_labels.append(family)
                    type_labels.append(mtype)
                    shas.append(sha)

                if new_cache_rows:
                    self._append_cache_rows(new_cache_rows)

                if features_list:
                    x_batch = np.vstack(features_list).astype(np.float32, copy=False)
                    yield x_batch, family_labels, type_labels, shas

                del features_list
                del family_labels
                del type_labels
                del shas
                gc.collect()
        except MemoryError as exc:
            logger.error("Out of memory in load_samples_batch: %s", exc)
            gc.collect()
            return
        except Exception as exc:
            logger.error("load_samples_batch failed: %s", exc, exc_info=True)
            return


# ADDED_ML: Module-level compatibility helpers requested by integration spec.
_DEFAULT_LOADER = AvastDatasetLoader()


def get_total_sample_count() -> int:
    return _DEFAULT_LOADER.get_total_sample_count()


def load_samples_batch(
    batch_size: int = 500,
    start_index: int = 0,
    max_samples: int | None = None,
):
    return _DEFAULT_LOADER.load_samples_batch(
        batch_size=batch_size,
        start_index=start_index,
        max_samples=max_samples,
    )
