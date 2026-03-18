import json
import re
from typing import Any, Dict, Optional


class JSONExtractor:
    def extract(self, response: str) -> Any:
        if not response:
            return {"error": "Empty response"}

        cleaned = response.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Prefer complete JSON blocks and try larger candidates first.
        candidates = []

        fenced_blocks = re.findall(
            r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned, re.IGNORECASE
        )
        candidates.extend(fenced_blocks)

        candidates.extend(self._extract_balanced_json_objects(cleaned))
        for block in fenced_blocks:
            candidates.extend(self._extract_balanced_json_objects(block))

        seen = set()
        unique_candidates = []
        for candidate in candidates:
            text = candidate.strip()
            if text and text not in seen:
                seen.add(text)
                unique_candidates.append(text)

        for candidate in sorted(unique_candidates, key=len, reverse=True):
            try:
                json_text = self._clean_json(candidate)
                parsed = json.loads(json_text)
                return parsed
            except json.JSONDecodeError:
                continue

        if len(cleaned) > 300:
            structured = self._structure_text(cleaned)
            if structured:
                return structured

            return {
                "analysis_text": cleaned,
                "parse_warning": "Response not in JSON format",
                "response_length": len(cleaned),
            }

        return {
            "error": "No valid JSON response",
            "raw_preview": cleaned[:500] if cleaned else "Empty",
            "response_length": len(cleaned),
        }

    def _clean_json(self, text: str) -> str:
        text = text.strip()
        text = re.sub(r",\s*}", "}", text)
        text = re.sub(r",\s*]", "]", text)

        open_braces = text.count("{")
        close_braces = text.count("}")

        if open_braces > close_braces:
            text += "}" * (open_braces - close_braces)

        return text

    def _extract_balanced_json_objects(self, text: str) -> list[str]:
        """Extract balanced top-level JSON object substrings from free text."""
        objects = []
        depth = 0
        start_idx = None

        for idx, char in enumerate(text):
            if char == "{":
                if depth == 0:
                    start_idx = idx
                depth += 1
            elif char == "}":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start_idx is not None:
                        objects.append(text[start_idx : idx + 1])
                        start_idx = None

        return objects

    def _structure_text(self, text: str) -> Optional[Dict[str, Any]]:
        import re

        try:
            sections = {}

            exec_match = re.search(
                r"(?:executive summary|overview|summary)[:\s]*([^\n].*?)(?=\n\n|\n[A-Z]|\Z)",
                text,
                re.IGNORECASE | re.DOTALL,
            )
            if exec_match:
                sections["executive_summary"] = {
                    "overview": exec_match.group(1).strip(),
                    "extracted_from_text": True,
                }

            behaviors_match = re.search(
                r"(?:key behaviors|key findings|behaviors)[:\s]*([^\n].*?)(?=\n\n|\n[A-Z]|\Z)",
                text,
                re.IGNORECASE | re.DOTALL,
            )
            if behaviors_match:
                behaviors_text = behaviors_match.group(1)
                behaviors_list = re.findall(r"[•\-*]\s*([^\n]+)", behaviors_text)
                sections["key_behaviors"] = (
                    behaviors_list if behaviors_list else [behaviors_text.strip()]
                )

            threat_match = re.search(
                r"(?:threat level|threat activity level|risk level)[:\s]*([^\n]+)",
                text,
                re.IGNORECASE,
            )
            if threat_match:
                sections["threat_assessment"] = {
                    "level": threat_match.group(1).strip(),
                    "extracted_from_text": True,
                }

            if sections:
                return {**sections, "structured_from_text": True}

            return None

        except Exception:
            return None
