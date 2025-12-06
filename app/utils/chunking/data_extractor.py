from typing import Any, Dict


class TokenEstimator:
    BEHAVIOR_PROCESS = 120
    BEHAVIOR_API_CALL = 8
    STRING_ITEM = 3
    MEMORY_ENTRY = 80
    ANOMALY_ITEM = 25
    PROCESSTREE_NODE = 40
    ENHANCED_EVENT = 30
    ENCRYPTED_BUFFER = 20
    YARA_RULE = 20
    ADDRESS_SPACE_ENTRY = 15

    @classmethod
    def estimate_behavior_tokens(cls, chunk_data: Dict[str, Any]) -> int:
        tokens = 0

        for process in chunk_data.get("processes", []):
            tokens += cls.BEHAVIOR_PROCESS
            tokens += len(process.get("calls", [])) * cls.BEHAVIOR_API_CALL

        tokens += len(chunk_data.get("anomaly", [])) * cls.ANOMALY_ITEM
        tokens += len(chunk_data.get("processtree", [])) * cls.PROCESSTREE_NODE
        tokens += len(chunk_data.get("enhanced", [])) * cls.ENHANCED_EVENT
        tokens += len(chunk_data.get("encryptedbuffers", [])) * cls.ENCRYPTED_BUFFER

        return tokens

    @classmethod
    def estimate_strings_tokens(cls, chunk_data: Dict[str, Any]) -> int:
        return sum(
            len(strings) * cls.STRING_ITEM
            for strings in chunk_data.get("categories", {}).values()
        )

    @classmethod
    def estimate_memory_tokens(cls, chunk_data: Dict[str, Any]) -> int:
        tokens = 0

        for entry in chunk_data.get("procmemory", []):
            tokens += cls.MEMORY_ENTRY
            tokens += len(entry.get("yara", [])) * cls.YARA_RULE
            tokens += len(entry.get("cape_yara", [])) * cls.YARA_RULE
            tokens += len(entry.get("address_space", [])) * cls.ADDRESS_SPACE_ENTRY

        return tokens
