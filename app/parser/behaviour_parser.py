import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.models.behaviourModel import Behaviour, SummaryModel

HIGH_VALUE_CALL_CATEGORIES = {
    "process",
    "registry",
    "filesystem",
    "network",
    "system",
    "crypto",
    "memory",
    "hooking",
}

EXCLUDE_CALL_FIELDS = {
    "thread_id",
    "caller",
    "parentcaller",
    "repeated",
    "pretty_return",
}

EXCLUDE_PROCESS_FIELDS = {"first_seen", "threads"}

CRITICAL_ENV_VARS = {
    "UserName",
    "ComputerName",
    "TempPath",
    "CommandLine",
    "Bitness",
}

EXCLUDE_TREENODE_FIELDS = {"threads", "environ"}


def filter_files(paths: List[str], action: str = "READ") -> List[str]:
    if not paths:
        return []

    if action.upper() in ["WRITE", "DELETE"]:
        return list(
            set(
                p
                for p in paths
                if p.lower().strip()
                not in ["c:\\", "c:\\users", "c:\\windows", "c:\\inetpub"]
            )
        )

    persistence_locations = [
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
        "\\programdata\\",
        "\\inetpub\\wwwroot\\",
        "\\desktop_",
        "\\physicaldrive",
    ]

    noise_locations = [
        "\\system32\\",
        "\\syswow64\\",
        "\\windows\\",
        "\\program files",
        "\\users\\cape\\appdata\\local\\microsoft\\windows\\caches\\",
    ]

    suspicious_terms = ["netwire", "revenge", ".exe", "gnil", "spoclsv"]
    results = []

    for path in paths:
        lower = path.lower()

        if any(
            n in lower and lower.endswith((".dll", ".mun", ".nls", ".dat", ".db"))
            for n in noise_locations
        ):
            continue

        if any(loc in lower for loc in persistence_locations) or any(
            term in lower for term in suspicious_terms
        ):
            results.append(path)

    return list(set(results))


def filter_enhanced_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not events:
        return []

    suspicious_locations = [
        "\\appdata\\local\\temp\\",
        "\\programdata\\",
        "\\inetpub\\wwwroot\\",
        "\\users\\",
    ]

    exclude_fields = {"eid", "timestamp", "object"}
    filtered = []

    for evt in events:
        event_copy = evt.copy()
        name = event_copy.get("event", "").lower()

        if name not in ["load", "unload"]:
            add = True
        else:
            data = event_copy.get("data", {})
            file_path = data.get("pathtofile") or data.get("file")
            if isinstance(file_path, str):
                lower = file_path.lower()
                system_dir = any(
                    s in lower for s in ["\\system32\\", "\\syswow64\\", "\\windows\\"]
                )
                suspicious = any(s in lower for s in suspicious_locations)
                add = suspicious and not system_dir
            else:
                add = False

        if add:
            for f in exclude_fields:
                event_copy.pop(f, None)
            if "data" in event_copy:
                event_copy["data"].pop("moduleaddress", None)
                event_copy["data"].pop("pathtofile", None)
            filtered.append(event_copy)

    return filtered


def filter_summary(summary: Optional[SummaryModel]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    result["summary_status"] = "Filtered to Actionable IOCs"

    if not summary:
        result["summary_status"] = "No Summary Data Provided"
        return result

    raw = summary.model_dump(exclude_defaults=True)

    file_actions = {
        "files": "ACCESS",
        "read_files": "READ",
        "write_files": "WRITE",
        "delete_files": "DELETE",
    }

    for key, action in file_actions.items():
        items = raw.get(key, [])
        if items:
            filtered = filter_files(items, action=action)
            result[key] = (
                filtered
                if filtered or action in ["WRITE", "DELETE"]
                else "CLEAN (0 items after filtering)"
            )
        else:
            result[key] = "CLEAN (0 items)"

    key_groups = ["read_keys", "write_keys", "delete_keys", "keys"]
    for key in key_groups:
        vals = raw.get(key, [])
        result[key] = list(set(vals)) if vals else "CLEAN (0 items)"

    high_value = [
        "executed_commands",
        "resolved_apis",
        "mutexes",
        "created_services",
        "started_services",
    ]

    for field in high_value:
        vals = raw.get(field)
        result[field] = list(set(vals)) if vals else "CLEAN (0 items)"

    return result


def filter_tree(node: Dict[str, Any]) -> Dict[str, Any]:
    for f in EXCLUDE_TREENODE_FIELDS:
        node.pop(f, None)

    if isinstance(node.get("children"), list):
        node["children"] = [filter_tree(child) for child in node["children"]]

    return node


def filter_env_vars(env: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in env.items() if k in CRITICAL_ENV_VARS}


def filter_calls(calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    result = []
    for call in calls:
        if (
            call.get("category") in HIGH_VALUE_CALL_CATEGORIES
            and call.get("status") is True
        ):
            filtered = {k: v for k, v in call.items() if k not in EXCLUDE_CALL_FIELDS}
            result.append(filtered)
    return result


def parse_and_filter_report(path: str) -> Optional[Tuple[Dict[str, Any], int, int]]:
    try:
        if not os.path.exists(path):
            print(f"❌ Error: File not found at {path}")
            return None

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        behavior = data.get("behavior")
        compact = json.dumps(behavior, separators=(",", ":"))
        original_size = len(compact.encode("utf-8"))

        behaviour_obj: Behaviour = Behaviour.model_validate(behavior)
        print("✅ Pydantic validation successful!")

    except Exception as e:
        print(f"❌ Pydantic Validation Failed: {e}")
        return None

    filtered = behaviour_obj.model_dump(exclude_none=True, exclude_defaults=True)

    processed = []
    for proc in filtered.get("processes", []):
        proc["calls"] = filter_calls(proc.get("calls", []))
        if isinstance(proc.get("environ"), dict):
            proc["environ"] = filter_env_vars(proc["environ"])
        for f in EXCLUDE_PROCESS_FIELDS:
            proc.pop(f, None)
        processed.append(proc)

    filtered["processes"] = processed

    if "processtree" in filtered:
        filtered["processtree"] = [filter_tree(n) for n in filtered["processtree"]]

    if behaviour_obj.summary:
        filtered["summary"] = filter_summary(behaviour_obj.summary)

    if filtered.get("enhanced"):
        filtered["enhanced"] = filter_enhanced_events(filtered["enhanced"])
    else:
        filtered.pop("enhanced", None)

    final_json = json.dumps(filtered, separators=(",", ":"))
    final_size = len(final_json.encode("utf-8"))

    return filtered, original_size, final_size


def format_size(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    if size >= 1024:
        return f"{size / 1024:.2f} KB"
    return f"{size} Bytes"


def get_call_category_distribution(path: str) -> Dict[str, int]:
    from collections import defaultdict

    try:
        if not os.path.exists(path):
            print(f"❌ Error: File not found at {path}")
            return {}
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Error reading JSON: {e}")
        return {}

    behavior = data.get("behavior")
    if not behavior:
        print("❌ Error: 'behavior' key missing.")
        return {}

    try:
        obj = Behaviour.model_validate(behavior)
    except Exception as e:
        print(f"❌ Validation Failed: {e}")
        return {}

    counts = defaultdict(int)
    for proc in obj.processes:
        for call in proc.calls:
            counts[call.category] += 1

    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


if __name__ == "__main__":
    script_dir = Path(__file__).parent
    base_dir = script_dir.parent
    input_dir = base_dir / "sample_reports"
    filename = "70_report.json"
    report_path = input_dir / filename

    output_dir = base_dir / "parsed_outputs"
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / (report_path.stem + "_parsed.json")

    if not report_path.exists():
        print(f"🛑 Missing: {report_path}")
        sys.exit(1)

    parsed = parse_and_filter_report(str(report_path))

    if parsed:
        filtered, orig_size, new_size = parsed
        reduction = ((orig_size - new_size) / orig_size) * 100

        print("\n" + "=" * 70)
        print("📊 SIZE REDUCTION ANALYSIS")
        print("=" * 70)
        print(f"Original: {format_size(orig_size)}")
        print(f"Filtered: {format_size(new_size)}")
        print(f"Reduction: {reduction:.2f}%")
        print("=" * 70)

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(filtered, f, indent=4)
            print(f"\n✅ Output written to: {output_path}")
        except Exception as e:
            print(f"❌ Write Error: {e}")
