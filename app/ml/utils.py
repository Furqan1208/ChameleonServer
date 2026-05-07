# ADDED_ML: Shared ML utilities (safe JSON handling, entropy, suspicious pattern extraction).
import json
import logging
import math
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable

logger = logging.getLogger(__name__)


def safe_file_read(file_path: str | Path) -> Dict[str, Any] | None:
    """Safely load a JSON file and return a dict, or None on failure."""
    try:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return None
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception as exc:
        logger.warning("safe_file_read failed for %s: %s", file_path, exc)
        return None


def calculate_entropy(values: Iterable[str]) -> float:
    """Calculate Shannon entropy across a list of strings."""
    try:
        joined = "|".join(str(v) for v in values if v)
        if not joined:
            return 0.0
        counts = Counter(joined)
        total = len(joined)
        entropy = 0.0
        for cnt in counts.values():
            p = cnt / total
            entropy -= p * math.log2(p)
        return float(entropy)
    except Exception as exc:
        logger.warning("calculate_entropy failed: %s", exc)
        return 0.0


def normalize_json_structure(report: Dict[str, Any] | None) -> Dict[str, Any]:
    """
    Normalize Avast CAPE format and local CAPE format into a common structure:
    {
        "summary": {...}
    }
    """
    try:
        if not isinstance(report, dict):
            return {"summary": {}}

        # Avast style: behavior.summary
        behavior = report.get("behavior")
        if isinstance(behavior, dict) and isinstance(behavior.get("summary"), dict):
            return {"summary": behavior.get("summary", {})}

        # Local style: summary at top-level
        if isinstance(report.get("summary"), dict):
            return {"summary": report.get("summary", {})}

        # Parsed style fallback: sections.behavior.data.summary
        sections = report.get("sections", {})
        if isinstance(sections, dict):
            behavior_section = sections.get("behavior", {})
            if isinstance(behavior_section, dict):
                behavior_data = behavior_section.get("data", {})
                if isinstance(behavior_data, dict) and isinstance(
                    behavior_data.get("summary"), dict
                ):
                    return {"summary": behavior_data.get("summary", {})}
                if isinstance(behavior_section.get("summary"), dict):
                    return {"summary": behavior_section.get("summary", {})}

        return {"summary": {}}
    except Exception as exc:
        logger.warning("normalize_json_structure failed: %s", exc)
        return {"summary": {}}


def extract_suspicious_patterns(summary: Dict[str, Any]) -> Dict[str, int]:
    """Extract simple binary suspicious-pattern flags from paths and commands."""
    try:
        files = []
        for key in ("files", "read_files", "write_files", "delete_files"):
            vals = summary.get(key, [])
            if isinstance(vals, list):
                files.extend(str(v).lower() for v in vals)

        keys = []
        for key_name in ("keys", "read_keys", "write_keys", "delete_keys"):
            vals = summary.get(key_name, [])
            if isinstance(vals, list):
                keys.extend(str(v).lower() for v in vals)

        commands = [
            str(v).lower()
            for v in summary.get("executed_commands", [])
            if isinstance(v, (str, int, float))
        ]

        joined_paths = " ".join(files + keys)
        joined_cmds = " ".join(commands)

        return {
            "flag_temp_path": int("\\temp\\" in joined_paths or "/temp/" in joined_paths),
            "flag_system32_path": int("system32" in joined_paths),
            "flag_appdata_path": int("appdata" in joined_paths),
            "flag_startup_path": int("startup" in joined_paths),
            "flag_programdata_path": int("programdata" in joined_paths),
            "flag_powershell_exec": int("powershell" in joined_cmds),
            "flag_cmd_or_rundll": int("cmd.exe" in joined_cmds or "rundll32" in joined_cmds),
        }
    except Exception as exc:
        logger.warning("extract_suspicious_patterns failed: %s", exc)
        return {
            "flag_temp_path": 0,
            "flag_system32_path": 0,
            "flag_appdata_path": 0,
            "flag_startup_path": 0,
            "flag_programdata_path": 0,
            "flag_powershell_exec": 0,
            "flag_cmd_or_rundll": 0,
        }
