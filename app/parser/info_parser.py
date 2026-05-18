import json
from pathlib import Path
from typing import Any, Dict, Optional

from app.models.analysisInfoModel import InfoModel, InfoPayload, InfoSummary
from app.utils.logger import get_logger

_logger = get_logger("app.parser.info")


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
        _logger.exception("Error reading report file: %s", error)
        return None


def prepare_cleaned_info(
    raw_info: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not raw_info:
        return None

    try:
        validated_info = InfoModel(**raw_info)

        # Clean raw fields we keep
        raw_clean = {
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
            "options": validated_info.options,
        }

        machine_info = None
        if validated_info.machine:
            machine_info = {
                "name": validated_info.machine.name,
                "platform": validated_info.machine.platform,
                "ip": validated_info.machine.ip,
                "status": validated_info.machine.status,
                "started_on": validated_info.machine.started_on,
                "shutdown_on": validated_info.machine.shutdown_on,
            }
            raw_clean["machine"] = machine_info

        # Build compact summary for AI
        if machine_info and machine_info.get("status") == "stopped":
            completion = "Completed"
        elif validated_info.timeout:
            completion = "Timeout"
        else:
            completion = "Abnormal"

        if validated_info.timeout or (machine_info and machine_info.get("status") != "stopped"):
            env_assessment = "Concerning"
        else:
            env_assessment = "Standard"

        summary = InfoSummary(
            sandbox_platform=machine_info.get("platform") if machine_info else None,
            analysis_type=validated_info.category,
            package_used=validated_info.package,
            execution_completion_status=completion,
            total_duration_seconds=validated_info.duration,
            timeout=validated_info.timeout,
            machine_status=machine_info.get("status") if machine_info else None,
        )

        payload = InfoPayload(raw=validated_info, summary=summary)
        return payload.model_dump(exclude_none=True)

    except Exception as error:
        _logger.exception("Error processing info data: %s", error)
        return None


def parse_info_section(report_path: Path) -> Optional[Dict[str, Any]]:
    raw_info = extract_info_data(report_path)
    return prepare_cleaned_info(raw_info)


def process_info_section(report_path: Path) -> Optional[Dict[str, Any]]:
    return parse_info_section(report_path)
