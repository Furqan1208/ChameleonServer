import json
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

        import re

        patterns = [
            r"```json\s*(\{.*\})\s*```",
            r"```\s*(\{.*\})\s*```",
            r"```json\s*(\{[\s\S]*?)\s*```",
            r"```\s*(\{[\s\S]*?)\s*```",
            r'(\{\s*"[^"]*"\s*:\s*[^}]*\})',
            r"^(\{[\s\S]*?\})(?:\n|$)",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, cleaned, re.DOTALL | re.MULTILINE)
            for match in matches:
                if not match:
                    continue

                try:
                    json_text = self._clean_json(match)
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
        import re

        text = text.strip()
        text = re.sub(r",\s*}", "}", text)
        text = re.sub(r",\s*]", "]", text)

        open_braces = text.count("{")
        close_braces = text.count("}")

        if open_braces > close_braces:
            text += "}" * (open_braces - close_braces)

        return text

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
