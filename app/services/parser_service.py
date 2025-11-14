import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

MODEL_FILES = {
    "behavior": "behavior_parser.py",
    "cape": "cape_processing_parser.py",
    "info": "info_parser.py",
    "memory": "memory_parser.py",
    "signatures": "signatures_malscore_malstatus_ttps_parser.py",
    "statistics": "statistics_parser.py",
    "strings": "strings_parser.py",
    "target": "target_parser.py",
}


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
            print(f"Error loading module {module_name} from {file_path}: {e}")
            return None

    def load_all_models(self):
        print("Loading model modules...")
        for model_name, filename in MODEL_FILES.items():
            model_path = self.models_dir / filename
            if model_path.exists():
                module = self.load_module(model_path, model_name)
                if module:
                    self.loaded_models[model_name] = module
                    print(f"   Loaded {model_name}")
            else:
                print(f"   Model file not found: {model_path}")


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
            print(f"Error extracting {section_name}: {e}")
            return None


class SectionParser:
    def __init__(self, model_loader: ModelLoader, report_extractor: ReportExtractor):
        self.model_loader = model_loader
        self.report_extractor = report_extractor

    def parse_behavior(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "behavior" not in self.model_loader.loaded_models:
            return None

        try:
            result = self.model_loader.loaded_models[
                "behavior"
            ].parse_and_filter_report(str(report_path))
            if result:
                filtered_data, original_size, filtered_size = result
                return {
                    "data": filtered_data,
                    "size_metrics": {
                        "original_bytes": original_size,
                        "filtered_bytes": filtered_size,
                        "reduction_percentage": (
                            (original_size - filtered_size) / original_size
                        )
                        * 100,
                    },
                }
            return None
        except Exception as e:
            print(f"Error parsing behavior: {e}")
            return None

    def parse_cape_section(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "cape" not in self.model_loader.loaded_models:
            return None

        try:
            cape_data = self.model_loader.loaded_models["cape"].extract_cape_section(
                report_path
            )
            cleaned = self.model_loader.loaded_models["cape"].clean_payloads(cape_data)
            return cleaned
        except Exception as e:
            print(f"Error parsing CAPE section: {e}")
            return None

    def parse_info(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "info" not in self.model_loader.loaded_models:
            return None

        try:
            cleaned_info = self.model_loader.loaded_models["info"].process_info_section(
                report_path
            )
            return cleaned_info
        except Exception as e:
            print(f"Error parsing info: {e}")
            return None

    def parse_memory(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "memory" not in self.model_loader.loaded_models:
            return None

        try:
            memory_section = self.model_loader.loaded_models[
                "memory"
            ].extract_memory_section(report_path)
            cleaned = self.model_loader.loaded_models["memory"].clean_memory_data(
                memory_section
            )
            return cleaned
        except Exception as e:
            print(f"Error parsing memory: {e}")
            return None

    def parse_signatures(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "signatures" not in self.model_loader.loaded_models:
            return None

        try:
            raw_sections = self.model_loader.loaded_models[
                "signatures"
            ].extract_detection_sections(report_path)
            cleaned = self.model_loader.loaded_models[
                "signatures"
            ].clean_detection_data(raw_sections)
            return cleaned
        except Exception as e:
            print(f"Error parsing signatures: {e}")
            return None

    def parse_statistics(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "statistics" not in self.model_loader.loaded_models:
            return None

        try:
            stat_section = self.model_loader.loaded_models[
                "statistics"
            ].extract_statistics_section(report_path)
            cleaned = self.model_loader.loaded_models["statistics"].clean_statistics(
                stat_section
            )
            return cleaned
        except Exception as e:
            print(f"Error parsing statistics: {e}")
            return None

    def parse_strings(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "strings" not in self.model_loader.loaded_models:
            return None

        try:
            results = self.model_loader.loaded_models["strings"].process_with_whitelist(
                report_path
            )
            return {
                "metadata": {
                    "strategy": "whitelist_only",
                    "total_strings_processed": results.total_processed,
                    "whitelisted_strings": len(results.clean_strings),
                    "garbage_removed": results.garbage_removed,
                    "reduction_percentage": f"{(results.garbage_removed / results.total_processed) * 100:.1f}%",  # noqa: E501
                    "whitelist_categories_used": list(results.categories.keys()),
                },
                "categories": results.categories,
                "all_clean_strings": results.clean_strings,
            }
        except Exception as e:
            print(f"Error parsing strings: {e}")
            return None

    def parse_target(self, report_path: Path) -> Optional[Dict[str, Any]]:
        if "target" not in self.model_loader.loaded_models:
            return None

        try:
            target_section = self.report_extractor.extract_section(
                report_path, "target"
            )
            if not target_section:
                return None

            target_model = self.model_loader.loaded_models[
                "target"
            ].TargetModel.from_dict(target_section)
            return target_model.model_dump(exclude_none=True)
        except Exception as e:
            print(f"Error parsing target: {e}")
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

        print(f"Analysis summary saved: {summary_file}")

    @staticmethod
    def _write_target_summary(results: Dict[str, Any], f):
        if "target" in results["sections"]:
            target = results["sections"]["target"]
            f.write("TARGET ANALYSIS:\n")
            f.write(f"  File: {target.get('file_name', 'N/A')}\n")
            f.write(f"  Size: {target.get('file_size', 'N/A')} bytes\n")
            f.write(f"  SHA256: {target.get('sha256', 'N/A')}\n")
            f.write(f"  Type: {target.get('file_type', 'N/A')}\n")
            f.write(f"  Signed: {target.get('pe_info', {}).get('signed', False)}\n")
            f.write(f"  YARA Hits: {target.get('yara_hits', 0)}\n\n")

    @staticmethod
    def _write_detection_summary(results: Dict[str, Any], f):
        if "signatures" in results["sections"]:
            sigs = results["sections"]["signatures"]
            f.write("DETECTION SUMMARY:\n")
            f.write(f"  MalScore: {sigs.get('malscore', 'N/A')}\n")
            f.write(f"  MalStatus: {sigs.get('malstatus', 'N/A')}\n")
            f.write(f"  Signatures: {len(sigs.get('signatures', []))}\n")
            f.write(f"  TTPs: {len(sigs.get('ttps', []))}\n\n")

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
            procs = memory.get("procmemory", [])
            f.write("MEMORY ANALYSIS:\n")
            f.write(f"  Processes Scanned: {len(procs)}\n")
            total_yara = sum(
                len(proc.get("yara", [])) + len(proc.get("cape_yara", []))
                for proc in procs
            )
            f.write(f"  Total YARA Hits: {total_yara}\n\n")

    @staticmethod
    def _write_strings_summary(results: Dict[str, Any], f):
        if "strings" in results["sections"]:
            strings = results["sections"]["strings"]
            meta = strings.get("metadata", {})
            f.write("STRINGS ANALYSIS:\n")
            f.write(f"  Total Strings: {meta.get('total_strings_processed', 0):,}\n")
            f.write(f"  Clean Strings: {meta.get('whitelisted_strings', 0):,}\n")
            f.write(f"  Garbage Removed: {meta.get('garbage_removed', 0):,}\n")
            f.write(f"  Reduction: {meta.get('reduction_percentage', '0%')}\n")


class CAPEMasterParser:
    def __init__(self, models_dir: Path):
        self.model_loader = ModelLoader(models_dir)
        self.report_extractor = ReportExtractor()
        self.section_parser = SectionParser(self.model_loader, self.report_extractor)
        self.output_manager = OutputManager()
        self.model_loader.load_all_models()

    def parse_complete_report(
        self, report_path: Path, output_dir: Path
    ) -> Dict[str, Any]:
        print(f"Parsing CAPE report: {report_path.name}")

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
            "target": self.section_parser.parse_target,
            "info": self.section_parser.parse_info,
            "behavior": self.section_parser.parse_behavior,
            "signatures": self.section_parser.parse_signatures,
            "memory": self.section_parser.parse_memory,
            "cape": self.section_parser.parse_cape_section,
            "statistics": self.section_parser.parse_statistics,
            "strings": self.section_parser.parse_strings,
        }

        for section_name, parser_method in parser_methods.items():
            print(f"   Parsing {section_name}...")
            section_data = parser_method(report_path)
            if section_data:
                results["sections"][section_name] = section_data
                results["metadata"]["sections_parsed"].append(section_name)

                section_file = individual_dir / f"{section_name}.json"
                self.output_manager.save_section_data(section_data, section_file)
                print(f"      Saved {section_file.name}")
            else:
                print(f"      No data for {section_name}")

        results["metadata"]["parsed_timestamp"] = datetime.now().isoformat()

        combined_file = analysis_dir / "combined_analysis.json"
        self.output_manager.save_section_data(results, combined_file)

        print(f"Combined analysis saved: {combined_file}")

        self.output_manager.create_summary(results, analysis_dir)

        return results


def main():
    if len(sys.argv) < 3:
        print(
            "Usage: python cape_master_parser.py <models_directory> <cape_report.json> [output_directory]"  # noqa: E501
        )
        print("\nArguments:")
        print("  models_directory   Directory containing all model Python files")
        print("  cape_report.json   CAPE analysis report to parse")
        print(
            " output_directory  (Optional) Output directory (default: ./parsed_reports)"
        )
        sys.exit(1)

    models_dir = Path(sys.argv[1])
    report_path = Path(sys.argv[2])
    output_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("./parsed_reports")

    if not models_dir.exists():
        print(f"Models directory not found: {models_dir}")
        sys.exit(1)

    if not report_path.exists():
        print(f"CAPE report not found: {report_path}")
        sys.exit(1)

    print("CAPE Master Parser - Starting Analysis")
    print(f"   Models Directory: {models_dir}")
    print(f"   Input Report: {report_path}")
    print(f"   Output Directory: {output_dir}")
    print()

    parser = CAPEMasterParser(models_dir)

    try:
        results = parser.parse_complete_report(report_path, output_dir)

        print("\n" + "=" * 60)
        print("ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"Output Location: {output_dir / report_path.stem}")
        print(f"Sections Processed: {len(results['metadata']['sections_parsed'])}")
        print(f"   {', '.join(results['metadata']['sections_parsed'])}")

        if "signatures" in results["sections"]:
            sigs = results["sections"]["signatures"]
            print(
                f"Detection: Score={sigs.get('malscore', 'N/A')}, Status={sigs.get('malstatus', 'N/A')}"  # noqa: E501
            )

        if "target" in results["sections"]:
            target = results["sections"]["target"]
            print(f"Target: {target.get('file_name')} ({target.get('file_type')})")

    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
