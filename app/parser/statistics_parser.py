import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.utils.filtration_and_extraction import clean_empty_values


def extract_statistics_data(report_path: Path) -> Dict[str, Any]:
    try:
        with open(report_path, "r", encoding="utf-8", errors="ignore") as file:
            data = json.load(file)

        if isinstance(data, dict):
            return data.get("statistics", {})
        elif isinstance(data, list):
            for item in data:
                if "statistics" in item:
                    return item["statistics"]
        return {}
    except Exception as error:
        print(f"Error extracting statistics data: {error}")
        return {}


def process_time_entries(entries: List[Dict[str, Any]]) -> tuple:
    processed_entries = []
    zero_time_entries = []

    for entry in entries:
        if isinstance(entry, dict) and entry.get("time", 0) > 0:
            name = entry.get("name")
            time_value = round(entry.get("time", 0), 3)
            processed_entries.append({name: time_value})
        elif isinstance(entry, dict) and entry.get("time", 0) == 0:
            zero_time_entries.append(entry)

    return processed_entries, zero_time_entries


def calculate_total_time(processed_entries: List[Dict[str, float]]) -> float:
    if not processed_entries:
        return 0.0
    return sum(entry[list(entry.keys())[0]] for entry in processed_entries)


def calculate_zero_time_weight(
    total_time: float, zero_processing_count: int, zero_signatures_count: int
) -> float:
    return total_time * (zero_processing_count + zero_signatures_count)


def clean_statistics(stat_data: Any) -> Dict[str, Any]:
    try:
        if not isinstance(stat_data, dict):
            return {}

        processing_entries = stat_data.get("processing", [])
        reporting_entries = stat_data.get("reporting", [])
        signature_entries = stat_data.get("signatures", [])

        processed_processing, zero_processing = process_time_entries(processing_entries)
        processed_reporting, _ = process_time_entries(reporting_entries)
        _, zero_signatures = process_time_entries(signature_entries)

        total_processing_time = calculate_total_time(processed_processing)
        zero_time_weight = calculate_zero_time_weight(
            total_processing_time, len(zero_processing), len(zero_signatures)
        )

        known_keys = {"processing", "reporting", "signatures"}
        extra_sections = {
            key: value
            for key, value in stat_data.items()
            if key not in known_keys and value not in [None, {}, [], ""]
        }
        extra_sections = clean_empty_values(extra_sections)

        cleaned_data = {
            "processing_summary": processed_processing,
            "reporting_summary": processed_reporting if processed_reporting else None,
            "total_processing_time": round(total_processing_time, 3)
            if total_processing_time
            else None,
            "zero_time_processing_count": len(zero_processing)
            if zero_processing
            else None,
            "zero_time_signatures_count": len(zero_signatures)
            if zero_signatures
            else None,
            "zero_time_weight": round(zero_time_weight, 3)
            if zero_time_weight
            else None,
            "extra_sections": extra_sections if extra_sections else None,
        }

        return clean_empty_values(cleaned_data)

    except Exception as error:
        print(f"Error cleaning statistics data: {error}")
        return {}


def save_cleaned_statistics(cleaned_data: Dict[str, Any], output_path: Path):
    try:
        cleaned_data = clean_empty_values(cleaned_data)
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(cleaned_data, file, indent=2)
        print(f"Statistics data saved to: {output_path}")
    except Exception as error:
        print(f"Error saving statistics data: {error}")


def process_statistics_section(report_path: Path) -> Optional[Dict[str, Any]]:
    statistics_data = extract_statistics_data(report_path)
    return clean_statistics(statistics_data)


def parse_statistics_section(report_path: Path) -> Optional[Dict[str, Any]]:
    return process_statistics_section(report_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python statistics_model.py <cape_report.json>")
        sys.exit(1)

    report_file = Path(sys.argv[1])
    output_file = report_file.stem + "_statistics_parsed.json"
    output_path = Path(output_file)

    statistics_data = extract_statistics_data(report_file)
    cleaned_data = clean_statistics(statistics_data)
    save_cleaned_statistics(cleaned_data, output_path)
