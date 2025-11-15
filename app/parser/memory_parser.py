import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.models.procmemoryModel import (
    MemoryMap,
    ProcessMemoryEntry,
    ProcMemoryProcessingResult,
)
from app.utils.filtration_and_extraction import (
    clean_empty_values,
    get_report_section,
)


def extract_memory_data(report_path: Path) -> Any:
    return get_report_section(report_path, "procmemory") or []


def normalize_yara_data(yara_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized_entries = []
    for entry in yara_list:
        if not isinstance(entry, dict):
            continue
        normalized_entry = {
            "name": entry.get("name"),
            "meta": entry.get("meta", {}),
            "strings": entry.get("strings", []),
            "addresses": entry.get("addresses", {}),
            "tags": entry.get("tags", []),
        }
        cleaned_entry = clean_empty_values(normalized_entry)
        if cleaned_entry:
            normalized_entries.append(cleaned_entry)
    return normalized_entries


def create_address_space_summary(
    address_list: List[MemoryMap],
) -> Optional[Dict[str, Any]]:
    if not address_list:
        return None

    total_regions = len(address_list)
    pe_regions = [region for region in address_list if region.PE is True]
    non_pe_regions = [region for region in address_list if region.PE is False]

    summary = {
        "total_regions": total_regions,
        "pe_regions": len(pe_regions),
        "non_pe_regions": len(non_pe_regions),
        "suspicious_regions": [
            {"start": region.start, "end": region.end} for region in pe_regions[:5]
        ],
    }
    return clean_empty_values(summary)


def process_memory_entries(process_entries):
    cleaned_entries = []
    for process in process_entries:
        yara_data = normalize_yara_data(process.yara)
        cape_yara_data = normalize_yara_data(
            [yara.dict() for yara in process.cape_yara] if process.cape_yara else []
        )

        address_summary = create_address_space_summary(process.address_space)

        processed_entry = {
            "pid": process.pid,
            "name": process.name,
            "sha256": process.sha256,
            "path": process.path,
            "yara": yara_data,
            "cape_yara": cape_yara_data,
            "address_space_summary": address_summary,
            "extracted_pe": process.extracted_pe,
            "_complete_data_available": True,
        }

        cleaned_entry = clean_empty_values(processed_entry)
        if cleaned_entry:
            cleaned_entries.append(cleaned_entry)

    return cleaned_entries


def clean_memory_data(memory_data: Any) -> Dict[str, Any]:
    if not memory_data:
        return {"procmemory": [], "metadata": {"status": "no_data"}}

    try:
        if isinstance(memory_data, dict):
            validated_data = ProcMemoryProcessingResult(**memory_data)
            processes = validated_data.procmemory
        elif isinstance(memory_data, list):
            processes = [
                ProcessMemoryEntry(**proc)
                for proc in memory_data
                if isinstance(proc, dict)
            ]
        else:
            processes = []

        cleaned_processes = process_memory_entries(processes)

        return {
            "procmemory": cleaned_processes,
            "metadata": {
                "total_processes": len(cleaned_processes),
                "validation_success": True,
                "complete_data_captured": True,
            },
        }

    except Exception as error:
        print(f"Memory data validation error: {error}")
        return clean_memory_data_fallback(memory_data)


def clean_memory_data_fallback(memory_data: Any) -> Dict[str, Any]:
    if isinstance(memory_data, dict):
        processes = memory_data.get("procmemory", [])
    elif isinstance(memory_data, list):
        processes = memory_data
    else:
        processes = []

    cleaned_processes = []
    for process in processes:
        if not isinstance(process, dict):
            continue

        yara_data = normalize_yara_data(process.get("yara", []))
        cape_yara_data = normalize_yara_data(process.get("cape_yara", []))
        address_summary = create_address_space_summary(process.get("address_space", []))

        processed_entry = {
            "pid": process.get("pid"),
            "name": process.get("name"),
            "sha256": process.get("sha256"),
            "path": process.get("path"),
            "yara": yara_data,
            "cape_yara": cape_yara_data,
            "address_space_summary": address_summary,
            "extracted_pe": process.get("extracted_pe"),
            "_complete_data_available": False,
        }

        cleaned_entry = clean_empty_values(processed_entry)
        if cleaned_entry:
            cleaned_processes.append(cleaned_entry)

    return {
        "procmemory": cleaned_processes,
        "metadata": {
            "total_processes": len(cleaned_processes),
            "validation_success": False,
            "complete_data_captured": False,
            "fallback_used": True,
        },
    }


def process_memory_section(report_path: Path) -> Optional[Dict[str, Any]]:
    memory_data = extract_memory_data(report_path)
    return clean_memory_data(memory_data)


def parse_memory_section(report_path: Path) -> Optional[Dict[str, Any]]:
    return process_memory_section(report_path)


def save_cleaned_memory(cleaned_data: Dict[str, Any], output_path: Path):
    cleaned_data = clean_empty_values(cleaned_data)
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(cleaned_data, file, indent=2)
    print(f"Memory data saved to: {output_path}")
