import json
from pathlib import Path
from typing import Any, Dict, Optional
from app.utils.logger import get_logger

_logger = get_logger("app.utils.filtration_and_extraction")


def clean_empty_values(data: Any) -> Any:
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            if value in (None, "", [], {}, "-", "null"):
                continue
            cleaned_value = clean_empty_values(value)
            if cleaned_value in (None, "", [], {}, "-", "null"):
                continue
            result[key] = cleaned_value
        return result
    elif isinstance(data, list):
        cleaned_items = [clean_empty_values(item) for item in data]
        return [
            item
            for item in cleaned_items
            if item not in (None, "", [], {}, "-", "null")
        ]
    else:
        return data


def get_report_section(report_path: Path, section_name: str) -> Any:
    try:
        with open(report_path, "r", encoding="utf-8") as file:
            content = json.load(file)

        if isinstance(content, list):
            for item in content:
                if section_name in item:
                    return item[section_name]
            return None
        elif isinstance(content, dict):
            return content.get(section_name)
        else:
            return None
    except Exception as error:
        _logger.exception("Error reading %s: %s", section_name, error)
        return None


def filter_data_fields(
    data: Dict[str, Any],
    include_fields: Optional[set] = None,
    exclude_fields: Optional[set] = None,
) -> Dict[str, Any]:
    filtered_data = {}

    for field, value in data.items():
        if include_fields and field not in include_fields:
            continue

        if exclude_fields and field in exclude_fields:
            continue

        if isinstance(value, dict):
            filtered_data[field] = filter_data_fields(value, set(), exclude_fields)
        elif isinstance(value, list):
            filtered_data[field] = [
                filter_data_fields(item, set(), exclude_fields)
                if isinstance(item, dict)
                else item
                for item in value
            ]
        else:
            filtered_data[field] = value

    return filtered_data


def write_cleaned_data(
    data: Dict[str, Any], output_path: Path, data_type: str = "data"
) -> None:
    cleaned_data = clean_empty_values(data)
    try:
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(cleaned_data, file, indent=2, ensure_ascii=False)
        _logger.info("Saved %s to: %s", data_type, output_path)
    except Exception as error:
        _logger.exception("Error saving %s: %s", data_type, error)
