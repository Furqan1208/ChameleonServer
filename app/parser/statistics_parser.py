import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.models.statisticsModel import (
    SignatureSummary,
    StatisticEntry,
    Statistics,
    StatisticsPayload,
    StatisticsSummary,
)
from app.utils.filtration_and_extraction import clean_empty_values
from app.utils.logger import get_logger

_logger = get_logger("app.parser.statistics")

_MAX_PROCESSING_PREVIEW = 12
_MAX_REPORTING_PREVIEW = 8
_MAX_SIGNATURE_PREVIEW = 12


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
        _logger.exception("Error extracting statistics data: %s", error)
        return {}


def _normalize_entry(entry: Any) -> Optional[StatisticEntry]:
    if not isinstance(entry, dict):
        return None

    name = entry.get("name")
    if not name:
        return None

    try:
        time_value = float(entry.get("time", 0) or 0)
    except (TypeError, ValueError):
        time_value = 0.0

    return StatisticEntry(name=str(name), time=round(time_value, 3))


def _normalize_entries(entries: Any) -> List[StatisticEntry]:
    if not isinstance(entries, list):
        return []

    normalized = []
    for entry in entries:
        parsed = _normalize_entry(entry)
        if parsed:
            normalized.append(parsed)
    return normalized


def _sort_entries(entries: List[StatisticEntry]) -> List[StatisticEntry]:
    return sorted(entries, key=lambda item: (-item.time, item.name.lower()))


def _summarize_entries(
    entries: List[StatisticEntry], limit: int
) -> List[StatisticEntry]:
    if not entries:
        return []

    sorted_entries = _sort_entries(entries)
    if len(sorted_entries) <= limit:
        return sorted_entries
    return sorted_entries[:limit]


def calculate_total_time(processed_entries: List[StatisticEntry]) -> float:
    if not processed_entries:
        return 0.0
    return sum(entry.time for entry in processed_entries)


def calculate_zero_time_weight(
    total_time: float, zero_processing_count: int, zero_signatures_count: int
) -> float:
    return total_time * (zero_processing_count + zero_signatures_count)


def clean_statistics(stat_data: Any) -> Dict[str, Any]:
    try:
        if not isinstance(stat_data, dict):
            return {}

        statistics = Statistics(
            processing=_normalize_entries(stat_data.get("processing", [])),
            reporting=_normalize_entries(stat_data.get("reporting", [])),
            signatures=_normalize_entries(stat_data.get("signatures", [])),
            extra_sections=clean_empty_values(
                {
                    key: value
                    for key, value in stat_data.items()
                    if key not in {"processing", "reporting", "signatures"}
                    and value not in [None, {}, [], ""]
                }
            ),
        )

        processing_entries = statistics.processing
        reporting_entries = statistics.reporting
        signature_entries = statistics.signatures

        zero_processing = [entry for entry in processing_entries if entry.time == 0]
        zero_signatures = [entry for entry in signature_entries if entry.time == 0]
        non_zero_processing = [entry for entry in processing_entries if entry.time > 0]
        non_zero_signatures = [entry for entry in signature_entries if entry.time > 0]

        total_processing_time = calculate_total_time(non_zero_processing)
        zero_time_weight = calculate_zero_time_weight(
            total_processing_time, len(zero_processing), len(zero_signatures)
        )

        processing_summary = _summarize_entries(
            non_zero_processing or processing_entries, _MAX_PROCESSING_PREVIEW
        )
        reporting_summary = _summarize_entries(
            reporting_entries, _MAX_REPORTING_PREVIEW
        )
        signatures_preview = _summarize_entries(
            signature_entries, _MAX_SIGNATURE_PREVIEW
        )

        max_processing = processing_summary[0] if processing_summary else None

        signatures_summary = SignatureSummary(
            total_count=len(signature_entries),
            zero_time_count=len(zero_signatures),
            non_zero_count=len(non_zero_signatures),
            top_entries=signatures_preview,
            truncated_entries=max(0, len(signature_entries) - len(signatures_preview)),
        )

        summary = StatisticsSummary(
            processing_summary=processing_summary,
            reporting_summary=reporting_summary,
            signatures_summary=signatures_summary,
            total_processing_time=round(total_processing_time, 3)
            if total_processing_time
            else None,
            max_processing_phase=max_processing.name if max_processing else None,
            max_processing_time=max_processing.time if max_processing else None,
            zero_time_processing_count=len(zero_processing) or None,
            zero_time_signatures_count=len(zero_signatures) or None,
            zero_time_weight=round(zero_time_weight, 3) if zero_time_weight else None,
            entry_counts={
                "processing": len(processing_entries),
                "reporting": len(reporting_entries),
                "signatures": len(signature_entries),
            },
            extra_sections=statistics.extra_sections,
        )

        payload = StatisticsPayload(raw=statistics, summary=summary)
        return clean_empty_values(payload.summary.model_dump(exclude_none=True))

    except Exception as error:
        _logger.exception("Error cleaning statistics data: %s", error)
        return {}


def save_cleaned_statistics(cleaned_data: Dict[str, Any], output_path: Path):
    try:
        cleaned_data = clean_empty_values(cleaned_data)
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(cleaned_data, file, indent=2)
        _logger.info("Statistics data saved to: %s", output_path)
    except Exception as error:
        _logger.exception("Error saving statistics data: %s", error)


def process_statistics_section(report_path: Path) -> Optional[Dict[str, Any]]:
    statistics_data = extract_statistics_data(report_path)
    return clean_statistics(statistics_data)


def parse_statistics_section(report_path: Path) -> Optional[Dict[str, Any]]:
    return process_statistics_section(report_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        _logger.info("Usage: python statistics_parser.py <cape_report.json>")
        sys.exit(1)

    report_file = Path(sys.argv[1])
    output_file = report_file.stem + "_statistics_parsed.json"
    output_path = Path(output_file)

    statistics_data = extract_statistics_data(report_file)
    cleaned_data = clean_statistics(statistics_data)
    save_cleaned_statistics(cleaned_data, output_path)
