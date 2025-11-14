import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.utils.filtration_and_extraction import (
    clean_empty_values,
)


class FileInfo(BaseModel):
    sha256: Optional[str] = None
    md5: Optional[str] = None
    cape_type: Optional[str] = None
    type: Optional[str] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    pid: Optional[Any] = None
    target_process: Optional[str] = None
    target_pid: Optional[Any] = None
    size: Optional[int] = None
    data: Optional[Any] = None
    die: Optional[List[Any]] = None

    class Config:
        extra = "ignore"


class CapePayloadSection(BaseModel):
    payloads: List[FileInfo] = Field(default_factory=list)

    class Config:
        extra = "ignore"


def extract_cape_data(report_path: Path) -> Dict[str, Any]:
    with open(report_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    cape_data = {}
    if isinstance(data, list):
        for item in data:
            if "CAPE" in item:
                cape_data = item["CAPE"]
                break
    elif isinstance(data, dict):
        cape_data = data.get("CAPE", {})

    return cape_data or {}


def filter_payloads(cape_data: Dict[str, Any]) -> Dict[str, Any]:
    payloads = cape_data.get("payloads", [])
    filtered_payloads = []

    for payload in payloads:
        filtered = {
            "sha256": payload.get("sha256"),
            "md5": payload.get("md5"),
            "cape_type": payload.get("cape_type"),
            "type": payload.get("type"),
            "process_name": payload.get("process_name"),
            "process_path": payload.get("process_path"),
            "pid": payload.get("pid"),
            "target_process": payload.get("target_process"),
            "target_pid": payload.get("target_pid"),
            "size": payload.get("size"),
            "data": payload.get("data"),
            "die": payload.get("die"),
        }
        filtered = clean_empty_values(filtered)
        if filtered:
            filtered_payloads.append(filtered)

    return {"payloads": filtered_payloads}


def save_filtered_report(filtered_data: Dict[str, Any], output_path: Path):
    filtered_data = clean_empty_values(filtered_data)
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(filtered_data, file, indent=2)
    print(f"Filtered CAPE section saved: {output_path}")


def process_cape_section(report_path: Path) -> Optional[Dict[str, Any]]:
    cape_data = extract_cape_data(report_path)
    return filter_payloads(cape_data)


def parse_cape_section(report_path: Path) -> Optional[Dict[str, Any]]:
    return process_cape_section(report_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cape_processing_model.py <cape_report.json>")
        sys.exit(1)

    report_file = Path(sys.argv[1])
    output_file = Path(report_file.stem + "_procmemory_parsed.json")

    cape_section = extract_cape_data(report_file)
    filtered_data = filter_payloads(cape_section)
    save_filtered_report(filtered_data, output_file)
