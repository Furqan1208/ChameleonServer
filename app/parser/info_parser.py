import json
from pathlib import Path
from typing import Any, Dict, Optional

from app.models.analysisInfoModel import InfoModel


def extract_info_data(file_path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            report_data = json.load(file)

        if isinstance(report_data, list):
            for item in report_data:
                if "info" in item:
                    return item["info"]
            return None
        elif isinstance(report_data, dict):
            return report_data.get("info")
        else:
            return None

    except Exception as error:
        print(f"Error reading report file: {error}")
        return None


def prepare_cleaned_info(
    raw_info: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not raw_info:
        return None

    try:
        validated_info = InfoModel(**raw_info)

        processed_data = {
            "version": validated_info.version,
            "id": validated_info.id,
            "category": validated_info.category,
            "package": validated_info.package,
            "started": validated_info.started,
            "ended": validated_info.ended,
            "duration": validated_info.duration,
            "timeout": validated_info.timeout,
            "route": validated_info.route,
            "CAPE_current_commit": validated_info.CAPE_current_commit,
        }

        if validated_info.machine:
            processed_data["machine"] = {
                "name": validated_info.machine.name,
                "platform": validated_info.machine.platform,
                "ip": validated_info.machine.ip,
                "status": validated_info.machine.status,
                "started_on": validated_info.machine.started_on,
                "shutdown_on": validated_info.machine.shutdown_on,
            }

        return processed_data

    except Exception as error:
        print(f"Error processing info data: {error}")
        return None


def parse_info_section(report_path: Path) -> Optional[Dict[str, Any]]:
    raw_info = extract_info_data(report_path)
    return prepare_cleaned_info(raw_info)


def process_info_section(report_path: Path) -> Optional[Dict[str, Any]]:
    return parse_info_section(report_path)
