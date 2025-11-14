#!/usr/bin/env python3
import importlib.util
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

MODEL_FILES = {
    "behavior": "behavior_model.py",
    "cape": "cape_processing_model.py",
    "info": "info_model.py",
    "memory": "memory_model.py",
    "signatures": "signatures_malscore_malstatus_ttps_model.py",
    "statistics": "statistics_model.py",
    "strings": "strings_model.py",
    "target": "target_model.py",
}


class CAPEMasterParser:
    def __init__(self, models_dir: Path):
        self.models_dir = models_dir
        self.loaded_models = {}
        self.load_models()

    def load_module(self, path: Path, name: str):
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            if not spec:
                raise ImportError(f"Spec load failed: {path}")
            module = importlib.util.module_from_spec(spec)
            if spec.loader is None:
                raise ImportError(f"Spec loader is None for: {path}")
            spec.loader.exec_module(module)
            return module
        except Exception:
            return None

    def load_models(self):
        for name, filename in MODEL_FILES.items():
            path = self.models_dir / filename
            if path.exists():
                mod = self.load_module(path, name)
                if mod:
                    self.loaded_models[name] = mod

    def load_section(self, report_path: Path, section: str) -> Any:
        try:
            with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    if section in item:
                        return item[section]
                return None
            if isinstance(data, dict):
                return data.get(section)
            return None
        except Exception:
            return None

    def parse_behavior(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "behavior" not in self.loaded_models:
            return None
        try:
            sec = self.load_section(report_path, "behavior")
            if not sec:
                return None
            result = self.loaded_models["behavior"].parse_and_filter_report(
                str(report_path)
            )
            if not result:
                return None
            filtered, orig, filt = result
            return {
                "data": filtered,
                "size_metrics": {
                    "original_bytes": orig,
                    "filtered_bytes": filt,
                    "reduction_percentage": ((orig - filt) / orig) * 100,
                },
            }
        except Exception:
            return None

    def parse_cape(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "cape" not in self.loaded_models:
            return None
        try:
            sec = self.loaded_models["cape"].extract_cape_section(report_path)
            return self.loaded_models["cape"].clean_payloads(sec)
        except Exception:
            return None

    def parse_info(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "info" not in self.loaded_models:
            return None
        try:
            return self.loaded_models["info"].process_info_section(report_path)
        except Exception:
            return None

    def parse_memory(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "memory" not in self.loaded_models:
            return None
        try:
            sec = self.loaded_models["memory"].extract_memory_section(report_path)
            return self.loaded_models["memory"].clean_memory_data(sec)
        except Exception:
            return None

    def parse_signatures(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "signatures" not in self.loaded_models:
            return None
        try:
            raw = self.loaded_models["signatures"].extract_detection_sections(
                report_path
            )
            return self.loaded_models["signatures"].clean_detection_data(raw)
        except Exception:
            return None

    def parse_statistics(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "statistics" not in self.loaded_models:
            return None
        try:
            sec = self.loaded_models["statistics"].extract_statistics_section(
                report_path
            )
            return self.loaded_models["statistics"].clean_statistics(sec)
        except Exception:
            return None

    def parse_strings(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "strings" not in self.loaded_models:
            return None
        try:
            res = self.loaded_models["strings"].process_with_whitelist(report_path)
            return {
                "metadata": {
                    "strategy": "whitelist_only",
                    "total_strings_processed": res.total_processed,
                    "whitelisted_strings": len(res.clean_strings),
                    "garbage_removed": res.garbage_removed,
                    "reduction_percentage": f"{(res.garbage_removed / res.total_processed) * 100:.1f}%",  # noqa: E501
                    "whitelist_categories_used": list(res.categories.keys()),
                },
                "categories": res.categories,
                "all_clean_strings": res.clean_strings,
            }
        except Exception:
            return None

    def parse_target(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "target" not in self.loaded_models:
            return None
        try:
            sec = self.load_section(report_path, "target")
            if not sec:
                return None
            model = self.loaded_models["target"].TargetModel.from_dict(sec)
            return model.model_dump(exclude_none=True)
        except Exception:
            return None

    def parse_full(self, report_path: Path, output_dir: Path) -> Dict[str, Any]:
        name = report_path.stem
        base = output_dir / name
        sec_dir = base / "individual_sections"
        sec_dir.mkdir(parents=True, exist_ok=True)

        results = {
            "metadata": {
                "original_report": report_path.name,
                "parsed_timestamp": None,
                "sections_parsed": [],
            },
            "sections": {},
        }

        parser_map = {
            "target": self.parse_target,
            "info": self.parse_info,
            "behavior": self.parse_behavior,
            "signatures": self.parse_signatures,
            "memory": self.parse_memory,
            "cape": self.parse_cape,
            "statistics": self.parse_statistics,
            "strings": self.parse_strings,
        }

        for sec, func in parser_map.items():
            data = func(report_path)
            if data:
                results["sections"][sec] = data
                results["metadata"]["sections_parsed"].append(sec)
                with open(sec_dir / f"{sec}.json", "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

        results["metadata"]["parsed_timestamp"] = datetime.now().isoformat()

        with open(base / "combined_analysis.json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        self.write_summary(results, base)
        return results

    def write_summary(self, results: Dict[str, Any], base: Path):
        file = base / "analysis_summary.txt"
        with open(file, "w", encoding="utf-8") as f:
            m = results["metadata"]
            f.write("CAPE REPORT ANALYSIS SUMMARY\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Original Report: {m['original_report']}\n")
            f.write(f"Parsed Timestamp: {m['parsed_timestamp']}\n")
            f.write(f"Sections Parsed: {', '.join(m['sections_parsed'])}\n\n")

            if "target" in results["sections"]:
                t = results["sections"]["target"]
                f.write("TARGET ANALYSIS:\n")
                f.write(f"  File: {t.get('file_name', 'N/A')}\n")
                f.write(f"  Size: {t.get('file_size', 'N/A')} bytes\n")
                f.write(f"  SHA256: {t.get('sha256', 'N/A')}\n")
                f.write(f"  Type: {t.get('file_type', 'N/A')}\n")
                f.write(f"  Signed: {t.get('pe_info', {}).get('signed', False)}\n")
                f.write(f"  YARA Hits: {t.get('yara_hits', 0)}\n\n")

            if "signatures" in results["sections"]:
                s = results["sections"]["signatures"]
                f.write("DETECTION SUMMARY:\n")
                f.write(f"  MalScore: {s.get('malscore', 'N/A')}\n")
                f.write(f"  MalStatus: {s.get('malstatus', 'N/A')}\n")
                f.write(f"  Signatures: {len(s.get('signatures', []))}\n")
                f.write(f"  TTPs: {len(s.get('ttps', []))}\n\n")
