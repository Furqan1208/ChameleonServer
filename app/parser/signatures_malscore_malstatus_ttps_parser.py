import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.utils.filtration_and_extraction import clean_empty_values


class SignatureEntry(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    categories: Optional[List[str]] = Field(default_factory=list)
    severity: Optional[int] = None
    confidence: Optional[int] = None
    families: Optional[List[str]] = Field(default_factory=list)
    data_summary: Optional[str] = None
    data: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

    class Config:
        extra = "ignore"


class TTPEntry(BaseModel):
    signature: Optional[str] = None
    ttps: Optional[List[str]] = Field(default_factory=list)
    mbcs: Optional[List[str]] = Field(default_factory=list)

    class Config:
        extra = "ignore"


class DetectionSummary(BaseModel):
    signatures: Optional[List[SignatureEntry]] = Field(default_factory=list)
    malscore: Optional[float] = None
    ttps: Optional[List[TTPEntry]] = Field(default_factory=list)
    malstatus: Optional[str] = None

    class Config:
        extra = "ignore"


def summarize_data_entries(
    data_list: List[Dict[str, Any]],
) -> Optional[str | List[Dict[str, Any]]]:
    if not data_list or not isinstance(data_list, list):
        return None

    if all(
        isinstance(entry, dict) and set(entry.keys()) <= {"type", "pid", "cid"}
        for entry in data_list
    ):
        pid = data_list[0].get("pid")
        cids = [entry["cid"] for entry in data_list if "cid" in entry]
        return f"Observed {len(cids)} API calls (pid: {pid}) with cids {cids}."

    return data_list


def extract_detection_data(report_path: Path) -> Dict[str, Any]:
    try:
        with open(report_path, "r", encoding="utf-8", errors="ignore") as file:
            data = json.load(file)

        if isinstance(data, list):
            combined_data = {}
            for item in data:
                if any(
                    key in item
                    for key in ["signatures", "malscore", "ttps", "malstatus"]
                ):
                    combined_data.update(item)
            return combined_data

        return {
            "signatures": data.get("signatures", []),
            "malscore": data.get("malscore"),
            "ttps": data.get("ttps", []),
            "malstatus": data.get("malstatus"),
        }
    except Exception as error:
        print(f"Error extracting detection data: {error}")
        return {}


def process_signature_data(signature):
    if not isinstance(signature, dict):
        return None

    data_field = signature.get("data") or []
    simplified_data = summarize_data_entries(data_field)

    processed_signature = {
        "name": signature.get("name"),
        "description": signature.get("description"),
        "categories": signature.get("categories"),
        "severity": signature.get("severity"),
        "confidence": signature.get("confidence"),
        "families": signature.get("families"),
    }

    if isinstance(simplified_data, str):
        processed_signature["data_summary"] = simplified_data
    elif isinstance(simplified_data, list):
        processed_signature["data"] = simplified_data

    return clean_empty_values(processed_signature)


def process_ttp_data(ttp_entry):
    if not isinstance(ttp_entry, dict):
        return None

    processed_ttp = {
        "signature": ttp_entry.get("signature"),
        "ttps": ttp_entry.get("ttps"),
        "mbcs": ttp_entry.get("mbcs"),
    }
    return clean_empty_values(processed_ttp)


def clean_detection_data(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        cleaned_signatures = []
        for signature in raw_data.get("signatures", []):
            processed = process_signature_data(signature)
            if processed:
                cleaned_signatures.append(processed)

        cleaned_ttps = []
        for ttp_entry in raw_data.get("ttps", []):
            processed = process_ttp_data(ttp_entry)
            if processed:
                cleaned_ttps.append(processed)

        output = {
            "signatures": cleaned_signatures,
            "malscore": raw_data.get("malscore"),
            "ttps": cleaned_ttps,
            "malstatus": raw_data.get("malstatus"),
        }

        return clean_empty_values(output)

    except Exception as error:
        print(f"Error cleaning detection data: {error}")
        return {}


def save_cleaned_detection(cleaned_data: Dict[str, Any], output_path: Path):
    try:
        cleaned_data = clean_empty_values(cleaned_data)
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(cleaned_data, file, indent=2)
        print(f"Detection data saved to: {output_path}")
    except Exception as error:
        print(f"Error saving detection data: {error}")


def process_detection_sections(report_path: Path) -> Optional[Dict[str, Any]]:
    raw_data = extract_detection_data(report_path)
    return clean_detection_data(raw_data)


def parse_detection_sections(report_path: Path) -> Optional[Dict[str, Any]]:
    return process_detection_sections(report_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python signatures_model.py <cape_report.json>")
        sys.exit(1)

    report_file = Path(sys.argv[1])
    output_file = Path(report_file.stem + "_detection_parsed.json")

    raw_data = extract_detection_data(report_file)
    cleaned_data = clean_detection_data(raw_data)
    save_cleaned_detection(cleaned_data, output_file)
