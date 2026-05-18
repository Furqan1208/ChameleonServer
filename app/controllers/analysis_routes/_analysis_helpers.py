from typing import Any, Dict


def extract_malscore(parsed_data: Dict[str, Any]) -> float:
    """Extract malscore from the supported parsed report shapes."""
    if not isinstance(parsed_data, dict):
        return 0.0

    sections = parsed_data.get("sections", {})
    if not isinstance(sections, dict):
        return 0.0

    signatures = sections.get("signatures", {})
    if not isinstance(signatures, dict):
        return 0.0

    candidates = [
        signatures.get("malscore"),
        signatures.get("ai_summary", {}).get("malscore")
        if isinstance(signatures.get("ai_summary"), dict)
        else None,
        signatures.get("full", {}).get("malscore")
        if isinstance(signatures.get("full"), dict)
        else None,
        parsed_data.get("malscore"),
        parsed_data.get("metadata", {}).get("malscore")
        if isinstance(parsed_data.get("metadata"), dict)
        else None,
    ]

    for candidate in candidates:
        if candidate is None:
            continue
        try:
            return float(candidate)
        except (TypeError, ValueError):
            continue

    return 0.0