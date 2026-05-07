# ADDED_ML: Memory-safe feature extraction for Avast and local CAPE-like reports.
import logging
import re
from pathlib import Path
from typing import Any, Dict, Iterable

import numpy as np

from app.ml.utils import calculate_entropy, extract_suspicious_patterns, normalize_json_structure

logger = logging.getLogger(__name__)

_API_TARGETS = [
    "createfile",
    "writefile",
    "readfile",
    "regopenkey",
    "regsetvalue",
    "internetopen",
    "urldownloadtofile",
    "createremotethread",
    "virtualalloc",
    "shellexecute",
]

_FEATURE_NAMES = [
    "api_createfile_count",
    "api_writefile_count",
    "api_readfile_count",
    "api_regopenkey_count",
    "api_regsetvalue_count",
    "api_internetopen_count",
    "api_urldownloadtofile_count",
    "api_createremotethread_count",
    "api_virtualalloc_count",
    "api_shellexecute_count",
    "total_file_ops_count",
    "read_files_count",
    "write_files_count",
    "delete_files_count",
    "total_registry_ops_count",
    "read_keys_count",
    "write_keys_count",
    "delete_keys_count",
    "executed_commands_count",
    "mutexes_count",
    "file_path_entropy",
    "registry_path_entropy",
    "unique_directories_accessed",
    "flag_temp_path",
    "flag_system32_path",
    "flag_appdata_path",
    "flag_startup_path",
    "flag_programdata_path",
    "flag_powershell_exec",
    "flag_cmd_or_rundll",
]


def get_feature_names() -> list[str]:
    return list(_FEATURE_NAMES)


def get_feature_count() -> int:
    return len(_FEATURE_NAMES)


def _safe_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _count_api_calls(summary: Dict[str, Any]) -> Dict[str, int]:
    resolved_apis = [str(v).lower() for v in _safe_list(summary.get("resolved_apis"))]

    # Avast behavior summary can store api_stats / apistats objects
    api_stats_candidates = [summary.get("api_stats"), summary.get("apistats")]
    api_stats_flat = []
    for candidate in api_stats_candidates:
        if isinstance(candidate, dict):
            for k, v in candidate.items():
                api_stats_flat.append(f"{k}:{v}")

    source_text = "\n".join(resolved_apis + api_stats_flat)

    counts = {}
    for api_name in _API_TARGETS:
        pattern = re.escape(api_name)
        counts[api_name] = len(re.findall(pattern, source_text))
    return counts


def _count_unique_directories(paths: Iterable[str]) -> int:
    dirs = set()
    for raw_path in paths:
        path = str(raw_path).replace("\\", "/").strip().lower()
        if not path:
            continue
        # Keep parent directory style abstraction to avoid extreme cardinality.
        parent = str(Path(path).parent)
        if parent and parent != ".":
            dirs.add(parent)
    return len(dirs)


def extract_features(report: Dict[str, Any] | None) -> np.ndarray:
    """Extract a stable float32 feature vector; returns all-zeros on failure."""
    try:
        normalized = normalize_json_structure(report)
        summary = normalized.get("summary", {}) if isinstance(normalized, dict) else {}
        if not isinstance(summary, dict):
            summary = {}

        files = _safe_list(summary.get("files"))
        read_files = _safe_list(summary.get("read_files"))
        write_files = _safe_list(summary.get("write_files"))
        delete_files = _safe_list(summary.get("delete_files"))

        keys = _safe_list(summary.get("keys"))
        read_keys = _safe_list(summary.get("read_keys"))
        write_keys = _safe_list(summary.get("write_keys"))
        delete_keys = _safe_list(summary.get("delete_keys"))

        executed_commands = _safe_list(summary.get("executed_commands"))
        mutexes = _safe_list(summary.get("mutexes"))

        api_counts = _count_api_calls(summary)

        total_file_ops = len(files) + len(read_files) + len(write_files) + len(delete_files)
        total_registry_ops = len(keys) + len(read_keys) + len(write_keys) + len(delete_keys)

        file_paths = [str(v) for v in files + read_files + write_files + delete_files]
        reg_paths = [str(v) for v in keys + read_keys + write_keys + delete_keys]

        suspicious = extract_suspicious_patterns(summary)

        feature_values = [
            float(api_counts.get("createfile", 0)),
            float(api_counts.get("writefile", 0)),
            float(api_counts.get("readfile", 0)),
            float(api_counts.get("regopenkey", 0)),
            float(api_counts.get("regsetvalue", 0)),
            float(api_counts.get("internetopen", 0)),
            float(api_counts.get("urldownloadtofile", 0)),
            float(api_counts.get("createremotethread", 0)),
            float(api_counts.get("virtualalloc", 0)),
            float(api_counts.get("shellexecute", 0)),
            float(total_file_ops),
            float(len(read_files)),
            float(len(write_files)),
            float(len(delete_files)),
            float(total_registry_ops),
            float(len(read_keys)),
            float(len(write_keys)),
            float(len(delete_keys)),
            float(len(executed_commands)),
            float(len(mutexes)),
            float(calculate_entropy(file_paths)),
            float(calculate_entropy(reg_paths)),
            float(_count_unique_directories(file_paths)),
            float(suspicious.get("flag_temp_path", 0)),
            float(suspicious.get("flag_system32_path", 0)),
            float(suspicious.get("flag_appdata_path", 0)),
            float(suspicious.get("flag_startup_path", 0)),
            float(suspicious.get("flag_programdata_path", 0)),
            float(suspicious.get("flag_powershell_exec", 0)),
            float(suspicious.get("flag_cmd_or_rundll", 0)),
        ]

        return np.asarray(feature_values, dtype=np.float32)
    except Exception as exc:
        logger.error("extract_features failed: %s", exc, exc_info=True)
        return np.zeros(get_feature_count(), dtype=np.float32)
