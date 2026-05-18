import importlib.util
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from app.utils.logger import get_logger

_logger = get_logger("app.services.parser")

MODEL_FILES = {
    "behavior": "behavior_parser.py",
    "cape": "cape_processing_parser.py",
    "info": "info_parser.py",
    "memory": "memory_parser.py",
    "network": "network_parser.py",
    "signatures": "signatures_malscore_malstatus_ttps_parser.py",
    "statistics": "statistics_parser.py",
    "strings": "strings_parser.py",
    "target": "target_parser.py",
}

# Limits for fallback extraction
_MAX_MEMORY_DUMPS_FALLBACK = 10


class ModelLoader:
    def __init__(self, models_dir: Path):
        self.models_dir = models_dir
        self.loaded_models = {}

    def load_module(self, file_path: Path, module_name: str):
        try:
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec is None or spec.loader is None:
                raise ImportError(f"Could not load spec or loader from {file_path}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception as e:
            _logger.exception("Error loading module %s from %s: %s", module_name, file_path, e)
            return None

    def load_all_models(self):
        _logger.info("Loading model modules...")
        for model_name, filename in MODEL_FILES.items():
            model_path = self.models_dir / filename
            if model_path.exists():
                module = self.load_module(model_path, model_name)
                if module:
                    self.loaded_models[model_name] = module
                    _logger.info("Loaded %s", model_name)
            else:
                _logger.warning("Model file not found: %s", model_path)


class ReportExtractor:
    @staticmethod
    def extract_section(report_path: Path, section_name: str) -> Any:
        try:
            with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            if isinstance(data, list):
                for item in data:
                    if section_name in item:
                        return item[section_name]
                return None
            elif isinstance(data, dict):
                return data.get(section_name)
            else:
                return None

        except Exception as e:
            _logger.exception("Error extracting %s: %s", section_name, e)
            return None


class SectionParser:
    def __init__(self, model_loader: ModelLoader, report_extractor: ReportExtractor):
        self.model_loader = model_loader
        self.report_extractor = report_extractor

    def parse_behavior(self, report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse Behavior section.
        Returns: { "full": {...}, "ai_summary": {...} } from the new parser.
        """
        if "behavior" not in self.model_loader.loaded_models:
            return None

        try:
            behavior_module = self.model_loader.loaded_models["behavior"]
            
            # New parser entrypoint
            if hasattr(behavior_module, "parse_behavior_section"):
                result = behavior_module.parse_behavior_section(report_path)
                if result:
                    _logger.info("Successfully parsed behavior using parse_behavior_section")
                    return result
            
            # Alternative entrypoint (direct class)
            if hasattr(behavior_module, "BehaviorParser") and hasattr(
                behavior_module.BehaviorParser, "parse"
            ):
                result = behavior_module.BehaviorParser.parse(report_path)
                if result:
                    _logger.info("Successfully parsed behavior using BehaviorParser.parse")
                    return result
            
            # Legacy method (fallback)
            if hasattr(behavior_module, "parse_and_filter_report"):
                result = behavior_module.parse_and_filter_report(str(report_path))
                if result:
                    filtered_data, original_size, filtered_size = result
                    return {
                        "data": filtered_data,
                        "size_metrics": {
                            "original_bytes": original_size,
                            "filtered_bytes": filtered_size,
                            "reduction_percentage": (
                                (original_size - filtered_size) / original_size
                            ) * 100,
                        },
                    }
            
            _logger.warning("No known parser method found for behavior section")
            return None
            
        except Exception as e:
            _logger.exception("Error parsing behavior: %s", e)
            return None

    def parse_cape_section(self, report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse CAPE section.
        Returns: { "full": {...}, "ai_summary": {...} } from the new parser.
        """
        if "cape" not in self.model_loader.loaded_models:
            return None

        try:
            cape_module = self.model_loader.loaded_models["cape"]

            # New parser entrypoint
            if hasattr(cape_module, "parse_cape_section"):
                result = cape_module.parse_cape_section(report_path)
                if result:
                    return result

            if hasattr(cape_module, "CAPEParser") and hasattr(
                cape_module.CAPEParser, "parse"
            ):
                result = cape_module.CAPEParser.parse(report_path)
                if result:
                    return result

            # Legacy methods
            if hasattr(cape_module, "extract_cape_data") and hasattr(
                cape_module, "filter_payloads"
            ):
                cape_data = cape_module.extract_cape_data(report_path)
                cleaned = cape_module.filter_payloads(cape_data)
                if cleaned:
                    return cleaned
            
            return self._build_cape_fallback(cape_module, report_path)
            
        except Exception as e:
            _logger.exception("Error parsing CAPE section: %s", e)
            return self._build_cape_fallback(None, report_path)

    def _build_cape_fallback(self, cape_module, report_path: Path) -> Optional[Dict[str, Any]]:
        """Build a minimal CAPE summary if parsing fails."""
        try:
            # Try to extract raw cape data
            if cape_module and hasattr(cape_module, 'extract_cape_data'):
                cape_data = cape_module.extract_cape_data(report_path)
            else:
                cape_data = self.report_extractor.extract_section(report_path, "CAPE")
            
            if not isinstance(cape_data, dict):
                return None

            payloads = cape_data.get("payloads", [])
            configs = cape_data.get("configs", [])

            if not isinstance(payloads, list):
                payloads = []
            if not isinstance(configs, list):
                configs = []

            summary = {
                "payload_count": len(payloads),
                "config_count": len(configs),
                "has_payloads": bool(payloads),
                "has_configs": bool(configs),
                "detected_families": [],
                "c2_servers": [],
                "quick_summary": f"CAPE extracted {len(payloads)} payloads and {len(configs)} configs"
            }

            return {
                "ai_summary": summary
            }
        except Exception as e:
            _logger.exception("Fallback CAPE parsing failed: %s", e)
            return None

    def parse_info(self, report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse Info section.
        Returns: { "raw": {...}, "summary": {...} } from the parser.
        """
        if "info" not in self.model_loader.loaded_models:
            return None

        try:
            info_module = self.model_loader.loaded_models["info"]
            
            if hasattr(info_module, 'parse_info_section'):
                result = info_module.parse_info_section(report_path)
                if result:
                    return result
            elif hasattr(info_module, 'process_info_section'):
                result = info_module.process_info_section(report_path)
                if result:
                    return result
            
            return None
        except Exception as e:
            _logger.exception("Error parsing info: %s", e)
            return None

    def parse_memory(self, report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse Memory sections (procdump, dropped, procmemory).
        Returns: { "full": {...}, "ai_summary": {...} } from the new parser.
        """
        if "memory" not in self.model_loader.loaded_models:
            return None

        try:
            memory_module = self.model_loader.loaded_models["memory"]
            
            # New parser entrypoint
            if hasattr(memory_module, "parse_memory_section"):
                result = memory_module.parse_memory_section(report_path)
                if result:
                    return result
            
            # Alternative entrypoint (direct class)
            if hasattr(memory_module, "MemoryParser") and hasattr(
                memory_module.MemoryParser, "parse"
            ):
                result = memory_module.MemoryParser.parse(report_path)
                if result:
                    return result
            
            # Legacy methods (fallback)
            if hasattr(memory_module, "extract_memory_data") and hasattr(
                memory_module, "clean_memory_data"
            ):
                memory_data = memory_module.extract_memory_data(report_path)
                cleaned = memory_module.clean_memory_data(memory_data)
                if cleaned:
                    return cleaned
            
            # Final fallback - try to extract raw and return minimal structure
            _logger.warning("No known parser method found for memory section, trying raw extraction")
            raw_procmemory = self.report_extractor.extract_section(report_path, "procmemory")
            raw_procdump = self.report_extractor.extract_section(report_path, "procdump")
            raw_dropped = self.report_extractor.extract_section(report_path, "dropped")

            def _strip_memory_dump(entry: Any) -> Any:
                if not isinstance(entry, dict):
                    return entry
                cleaned = entry.copy()
                cleaned.pop("address_space", None)
                cleaned.pop("strings_path", None)
                return cleaned

            def _strip_extracted_file(entry: Any) -> Any:
                if not isinstance(entry, dict):
                    return entry
                cleaned = entry.copy()
                cleaned.pop("strings", None)
                cleaned.pop("data", None)
                cleaned.pop("dirents", None)
                cleaned.pop("resources", None)
                cleaned.pop("versioninfo", None)
                cleaned.pop("icon", None)
                if "pe" in cleaned and isinstance(cleaned["pe"], dict):
                    pe = cleaned["pe"].copy()
                    pe.pop("strings", None)
                    pe.pop("dirents", None)
                    pe.pop("resources", None)
                    pe.pop("versioninfo", None)
                    pe.pop("icon", None)
                    cleaned["pe"] = pe
                return cleaned

            if isinstance(raw_procmemory, list):
                raw_procmemory = [_strip_memory_dump(item) for item in raw_procmemory]
            if isinstance(raw_procdump, list):
                raw_procdump = [_strip_extracted_file(item) for item in raw_procdump]
            if isinstance(raw_dropped, list):
                raw_dropped = [_strip_extracted_file(item) for item in raw_dropped]
            
            result = {
                "full": {
                    "procmemory": {
                        "memory_dumps": raw_procmemory[:_MAX_MEMORY_DUMPS_FALLBACK] if isinstance(raw_procmemory, list) else [],
                        "total_dumps": len(raw_procmemory) if isinstance(raw_procmemory, list) else 0,
                        "dumps_with_yara": 0,
                        "dumps_with_shellcode": 0,
                        "total_extracted_pe": 0
                    },
                    "procdump": {
                        "files": raw_procdump[:_MAX_MEMORY_DUMPS_FALLBACK] if isinstance(raw_procdump, list) else [],
                        "total_files": len(raw_procdump) if isinstance(raw_procdump, list) else 0,
                        "total_pe_files": 0,
                        "file_types": {}
                    },
                    "dropped": {
                        "files": raw_dropped[:_MAX_MEMORY_DUMPS_FALLBACK] if isinstance(raw_dropped, list) else [],
                        "total_files": len(raw_dropped) if isinstance(raw_dropped, list) else 0,
                        "file_types": {},
                        "suspicious_paths": []
                    }
                },
                "ai_summary": {
                    "total_procdump_files": len(raw_procdump) if isinstance(raw_procdump, list) else 0,
                    "total_dropped_files": len(raw_dropped) if isinstance(raw_dropped, list) else 0,
                    "total_memory_dumps": len(raw_procmemory) if isinstance(raw_procmemory, list) else 0,
                    "quick_summary": f"Found {len(raw_procmemory) if isinstance(raw_procmemory, list) else 0} memory dumps"
                }
            }
            return result
            
        except Exception as e:
            _logger.exception("Error parsing memory section: %s", e)
            return None

    def parse_signatures(self, report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse Signatures section (signatures, ttps, malscore, malstatus).
        Returns: { "full": {...}, "ai_summary": {...} } from the new parser.
        """
        if "signatures" not in self.model_loader.loaded_models:
            return None

        try:
            sig_module = self.model_loader.loaded_models["signatures"]
            
            # New parser entrypoint
            if hasattr(sig_module, "parse_signatures_section"):
                result = sig_module.parse_signatures_section(report_path)
                if result:
                    _logger.info("Successfully parsed signatures using parse_signatures_section")
                    return result
            
            # Alternative entrypoint (direct class)
            if hasattr(sig_module, "SignaturesParser") and hasattr(
                sig_module.SignaturesParser, "parse"
            ):
                result = sig_module.SignaturesParser.parse(report_path)
                if result:
                    _logger.info("Successfully parsed signatures using SignaturesParser.parse")
                    return result
            
            # Legacy methods (fallback)
            if hasattr(sig_module, "extract_detection_data") and hasattr(
                sig_module, "clean_detection_data"
            ):
                _logger.info("Using legacy extract_detection_data/clean_detection_data for signatures")
                raw_sections = sig_module.extract_detection_data(report_path)
                cleaned = sig_module.clean_detection_data(raw_sections)
                if cleaned:
                    return cleaned
            
            # Final fallback - try to extract raw and return minimal structure
            _logger.warning("No known parser method found for signatures section, using raw extraction fallback")
            raw_signatures = self.report_extractor.extract_section(report_path, "signatures")
            raw_ttps = self.report_extractor.extract_section(report_path, "ttps")
            
            # Extract malscore and malstatus from root
            raw_data = None
            try:
                with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                    raw_data = json.load(f)
            except Exception:
                pass
            
            raw_malscore = None
            raw_malstatus = None
            if isinstance(raw_data, dict):
                raw_malscore = raw_data.get("malscore")
                raw_malstatus = raw_data.get("malstatus")
            elif isinstance(raw_data, list):
                for item in raw_data:
                    if isinstance(item, dict):
                        if "malscore" in item:
                            raw_malscore = item.get("malscore")
                        if "malstatus" in item:
                            raw_malstatus = item.get("malstatus")
            
            # Count high severity signatures if possible
            high_severity_count = 0
            if isinstance(raw_signatures, list):
                for sig in raw_signatures:
                    if isinstance(sig, dict) and sig.get("severity", 0) >= 3:
                        high_severity_count += 1
            
            result = {
                "full": {
                    "signatures": {"signatures": raw_signatures if isinstance(raw_signatures, list) else []},
                    "ttps": {"mappings": raw_ttps if isinstance(raw_ttps, list) else []},
                    "malscore": raw_malscore if raw_malscore is not None else 0.0,
                    "malstatus": raw_malstatus if raw_malstatus else "unknown"
                },
                "ai_summary": {
                    "malscore": raw_malscore if raw_malscore is not None else 0.0,
                    "malstatus": raw_malstatus if raw_malstatus else "unknown",
                    "total_signatures": len(raw_signatures) if isinstance(raw_signatures, list) else 0,
                    "critical_signatures": high_severity_count,
                    "quick_summary": f"Found {len(raw_signatures) if isinstance(raw_signatures, list) else 0} signatures ({high_severity_count} high severity)"
                }
            }
            return result
            
        except Exception as e:
            _logger.exception("Error parsing signatures section: %s", e)
            return None

    def parse_statistics(self, report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse Statistics section.
        Returns the summary object directly (already compact).
        """
        if "statistics" not in self.model_loader.loaded_models:
            return None

        try:
            stats_module = self.model_loader.loaded_models["statistics"]
            
            if hasattr(stats_module, 'parse_statistics_section'):
                result = stats_module.parse_statistics_section(report_path)
                if result:
                    return result
            elif hasattr(stats_module, 'process_statistics_section'):
                result = stats_module.process_statistics_section(report_path)
                if result:
                    return result
            
            return None
        except Exception as e:
            _logger.exception("Error parsing statistics: %s", e)
            return None

    def parse_strings(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "strings" not in self.model_loader.loaded_models:
            return None

        try:
            results = self.model_loader.loaded_models[
                "strings"
            ].process_whitelist_filtering(report_path)
            return {
                "metadata": {
                    "strategy": "whitelist_only",
                    "total_strings_processed": results.total_processed,
                    "whitelisted_strings": len(results.clean_strings),
                    "garbage_removed": results.garbage_removed,
                    "reduction_percentage": f"{(results.garbage_removed / results.total_processed) * 100:.1f}%",
                    "whitelist_categories_used": list(results.categories.keys()),
                },
                "categories": results.categories,
                "all_clean_strings": results.clean_strings,
            }
        except Exception as e:
            _logger.exception("Error parsing strings: %s", e)
            return None

    def parse_network(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "network" not in self.model_loader.loaded_models:
            _logger.warning("Network parser module not loaded; skipping network section")
            return None

        try:
            network_module = self.model_loader.loaded_models["network"]

            if hasattr(network_module, "parse_network_section"):
                result = network_module.parse_network_section(report_path)
                if result:
                    return result

            if hasattr(network_module, "NetworkParser") and hasattr(
                network_module.NetworkParser, "parse"
            ):
                result = network_module.NetworkParser.parse(report_path)
                if result:
                    return result

            if hasattr(network_module, "process_network_section"):
                result = network_module.process_network_section(report_path)
                if result:
                    return result

            _logger.info("Network parser returned no data")
            return None
        except Exception as e:
            _logger.exception("Error parsing network: %s", e)
            return None
            return None

    def parse_target(self, report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse Target section.
        Returns: { "summary": {...}, "detections": [...], "detections2pid": {...} }
        """
        if "target" not in self.model_loader.loaded_models:
            return None

        try:
            target_module = self.model_loader.loaded_models["target"]
            
            if hasattr(target_module, 'parse_target_section'):
                result = target_module.parse_target_section(report_path)
                if result:
                    return result
            elif hasattr(target_module, 'process_target_section'):
                result = target_module.process_target_section(report_path)
                if result:
                    return result
            elif hasattr(target_module, 'TargetParser'):
                # New parser with parse method
                parser = target_module.TargetParser()
                result = parser.parse(report_path)
                if result:
                    return result.model_dump(exclude_none=True)
            
            return None
        except Exception as e:
            _logger.exception("Error parsing target: %s", e)
            return None


class OutputManager:
    @staticmethod
    def save_section_data(section_data: Dict[str, Any], section_file: Path):
        with open(section_file, "w", encoding="utf-8") as f:
            json.dump(section_data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def create_summary(results: Dict[str, Any], analysis_dir: Path):
        summary_file = analysis_dir / "analysis_summary.txt"

        with open(summary_file, "w", encoding="utf-8") as f:
            f.write("CAPE REPORT ANALYSIS SUMMARY\n")
            f.write("=" * 50 + "\n\n")

            metadata = results["metadata"]
            f.write(f"Original Report: {metadata['original_report']}\n")
            f.write(f"Parsed Timestamp: {metadata['parsed_timestamp']}\n")
            f.write(f"Sections Parsed: {', '.join(metadata['sections_parsed'])}\n\n")

            OutputManager._write_target_summary(results, f)
            OutputManager._write_detection_summary(results, f)
            OutputManager._write_behavior_summary(results, f)
            OutputManager._write_memory_summary(results, f)
            OutputManager._write_strings_summary(results, f)
            OutputManager._write_cape_summary(results, f)

        _logger.info("Analysis summary saved: %s", summary_file)

    @staticmethod
    def _write_target_summary(results: Dict[str, Any], f):
        if "target" in results["sections"]:
            target = results["sections"]["target"]
            # Handle both new and old formats
            if isinstance(target, dict):
                if "summary" in target:
                    summary = target["summary"]
                elif "ai_summary" in target:
                    summary = target["ai_summary"]
                else:
                    summary = target
            else:
                summary = {}
            
            f.write("TARGET ANALYSIS:\n")
            f.write(f"  File: {summary.get('file_name', 'N/A')}\n")
            f.write(f"  Size: {summary.get('file_size', 'N/A')} bytes\n")
            f.write(f"  SHA256: {summary.get('sha256', 'N/A')[:16] if summary.get('sha256') else 'N/A'}...\n")
            f.write(f"  Type: {summary.get('file_type', 'N/A')[:50] if summary.get('file_type') else 'N/A'}\n")
            f.write(f"  Signed: {summary.get('is_signed', False)}\n")
            f.write(f"  CAPE Type: {summary.get('cape_type', 'N/A')}\n")
            f.write(f"  Families: {', '.join(summary.get('detected_families', [])) or 'None'}\n\n")

    @staticmethod
    def _write_detection_summary(results: Dict[str, Any], f):
        if "signatures" in results["sections"]:
            signatures_data = results["sections"]["signatures"]
            # Handle new parser format
            if isinstance(signatures_data, dict):
                if "ai_summary" in signatures_data:
                    summary = signatures_data["ai_summary"]
                elif "full" in signatures_data:
                    full_data = signatures_data.get("full", {})
                    summary = {
                        "malscore": full_data.get("malscore", 0),
                        "malstatus": full_data.get("malstatus", "unknown"),
                        "total_signatures": len(full_data.get("signatures", {}).get("signatures", []))
                    }
                else:
                    summary = signatures_data
            else:
                summary = {}
            
            f.write("DETECTION SUMMARY:\n")
            f.write(f"  MalScore: {summary.get('malscore', 'N/A')}\n")
            f.write(f"  MalStatus: {summary.get('malstatus', 'N/A')}\n")
            f.write(f"  Total Signatures: {summary.get('total_signatures', 0)}\n")
            f.write(f"  Critical Signatures: {summary.get('critical_signatures', 0)}\n")
            f.write(f"  Domains: {len(summary.get('domains', []))}\n")
            f.write(f"  IPs: {len(summary.get('ips', []))}\n")
            f.write(f"  TTPs: {len(summary.get('detected_ttps', []))}\n\n")

    @staticmethod
    def _write_behavior_summary(results: Dict[str, Any], f):
        if "behavior" in results["sections"]:
            behavior = results["sections"]["behavior"]
            if "size_metrics" in behavior:
                metrics = behavior["size_metrics"]
                f.write("BEHAVIOR DATA:\n")
                f.write(
                    f"  Size Reduction: {metrics.get('reduction_percentage', 0):.1f}%\n"
                )
                f.write(f"  Original: {metrics.get('original_bytes', 0):,} bytes\n")
                f.write(f"  Filtered: {metrics.get('filtered_bytes', 0):,} bytes\n\n")

    @staticmethod
    def _write_memory_summary(results: Dict[str, Any], f):
        if "memory" in results["sections"]:
            memory = results["sections"]["memory"]
            # Handle new parser format with full/ai_summary
            if isinstance(memory, dict):
                if "ai_summary" in memory:
                    summary = memory["ai_summary"]
                elif "full" in memory:
                    # Extract from full if needed
                    full_data = memory.get("full", {})
                    procmemory = full_data.get("procmemory", {})
                    procdump = full_data.get("procdump", {})
                    dropped = full_data.get("dropped", {})
                    f.write("MEMORY ANALYSIS:\n")
                    f.write(f"  Procdump Files: {procdump.get('total_files', 0)}\n")
                    f.write(f"    - PE Files: {procdump.get('total_pe_files', 0)}\n")
                    f.write(f"  Dropped Files: {dropped.get('total_files', 0)}\n")
                    f.write(f"  Memory Dumps: {procmemory.get('total_dumps', 0)}\n")
                    f.write(f"    - With YARA: {procmemory.get('dumps_with_yara', 0)}\n")
                    f.write(f"    - With Shellcode: {procmemory.get('dumps_with_shellcode', 0)}\n")
                    f.write(f"    - Extracted PEs: {procmemory.get('total_extracted_pe', 0)}\n\n")
                    return
                else:
                    summary = memory
            else:
                summary = {}
            
            f.write("MEMORY ANALYSIS:\n")
            f.write(f"  Procdump Files: {summary.get('total_procdump_files', 0)}\n")
            f.write(f"  Dropped Files: {summary.get('total_dropped_files', 0)}\n")
            f.write(f"  Memory Dumps: {summary.get('total_memory_dumps', 0)}\n")
            f.write(f"  Memory YARA Hits: {summary.get('memory_dumps_with_yara', 0)}\n")
            f.write(f"  Shellcode Detected: {summary.get('memory_shellcode_detected', False)}\n")
            f.write(f"  Code Injection Detected: {summary.get('memory_injection_detected', False)}\n\n")

    @staticmethod
    def _write_strings_summary(results: Dict[str, Any], f):
        if "strings" in results["sections"]:
            strings = results["sections"]["strings"]
            meta = strings.get("metadata", {})
            f.write("STRINGS ANALYSIS:\n")
            f.write(f"  Total Strings: {meta.get('total_strings_processed', 0):,}\n")
            f.write(f"  Clean Strings: {meta.get('whitelisted_strings', 0):,}\n")
            f.write(f"  Garbage Removed: {meta.get('garbage_removed', 0):,}\n")
            f.write(f"  Reduction: {meta.get('reduction_percentage', '0%')}\n\n")

    @staticmethod
    def _write_cape_summary(results: Dict[str, Any], f):
        if "cape" in results["sections"]:
            cape = results["sections"]["cape"]
            # Handle new parser format with ai_summary
            if isinstance(cape, dict):
                if "ai_summary" in cape:
                    summary = cape["ai_summary"]
                elif "summary" in cape:
                    summary = cape["summary"]
                else:
                    summary = cape
            else:
                summary = {}
            
            f.write("CAPE EXTRACTION SUMMARY:\n")
            f.write(f"  Families: {', '.join(summary.get('detected_families', [])) or 'None'}\n")
            f.write(f"  Payloads: {summary.get('total_payloads', 0)}\n")
            f.write(f"  Configs: {summary.get('total_configs', 0)}\n")
            f.write(f"  C2 Servers: {', '.join(summary.get('c2_servers', [])[:3]) or 'None'}\n")
            f.write(f"  Injection: {summary.get('primary_injection_method', 'None')}\n\n")


class ParserService:
    def __init__(self, models_dir: Path):
        self.model_loader = ModelLoader(models_dir)
        self.report_extractor = ReportExtractor()
        self.section_parser = SectionParser(self.model_loader, self.report_extractor)
        self.output_manager = OutputManager()
        self.model_loader.load_all_models()

    def parse_complete_report(
        self, report_path: Path, output_dir: Path
    ) -> Dict[str, Any]:
        _logger.info("Parsing CAPE report: %s", report_path.name)

        report_stem = report_path.stem
        analysis_dir = output_dir / report_stem
        individual_dir = analysis_dir / "individual_sections"
        individual_dir.mkdir(parents=True, exist_ok=True)

        results = {
            "metadata": {
                "original_report": report_path.name,
                "parsed_timestamp": None,
                "sections_parsed": [],
            },
            "sections": {},
        }

        parser_methods = {
            "info": self.section_parser.parse_info,
            "statistics": self.section_parser.parse_statistics,
            "cape": self.section_parser.parse_cape_section,
            "target": self.section_parser.parse_target,
            "behavior": self.section_parser.parse_behavior,
            "signatures": self.section_parser.parse_signatures,
            "memory": self.section_parser.parse_memory,
            "network": self.section_parser.parse_network,
            "strings": self.section_parser.parse_strings,
        }

        for section_name, parser_method in parser_methods.items():
            _logger.info("Parsing section: %s", section_name)
            section_data = parser_method(report_path)
            if section_data:
                results["sections"][section_name] = section_data
                results["metadata"]["sections_parsed"].append(section_name)

                section_file = individual_dir / f"{section_name}.json"
                self.output_manager.save_section_data(section_data, section_file)
                _logger.info("Saved %s", section_file.name)
            else:
                _logger.info("No data for %s", section_name)

        results["metadata"]["parsed_timestamp"] = datetime.now().isoformat()

        combined_file = analysis_dir / "combined_analysis.json"
        self.output_manager.save_section_data(results, combined_file)

        _logger.info("Combined analysis saved: %s", combined_file)

        self.output_manager.create_summary(results, analysis_dir)

        return results