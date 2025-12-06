from dataclasses import dataclass


@dataclass
class TokenEstimationConfig:
    behavior_process: int = 120
    behavior_api_call: int = 8
    string_item: int = 3
    memory_entry: int = 80
    anomaly_item: int = 25
    processtree_node: int = 40
    enhanced_event: int = 30
    encrypted_buffer: int = 20
    yara_rule: int = 20
    address_space_entry: int = 15


@dataclass
class SectionChunkConfig:
    behavior_chunk_size: int = 3
    behavior_max_tokens: int = 8000

    strings_chunk_size: int = 2000
    strings_max_tokens: int = 6000

    memory_chunk_size: int = 10
    memory_max_tokens: int = 4000


class ChunkingConfiguration:
    def __init__(
        self,
        token_config: TokenEstimationConfig,
        section_config: SectionChunkConfig,
    ):
        self.token_config = token_config or TokenEstimationConfig()
        self.section_config = section_config or SectionChunkConfig()

    def get_chunk_size(self, section_type: str) -> int:
        mapping = {
            "behavior": self.section_config.behavior_chunk_size,
            "strings": self.section_config.strings_chunk_size,
            "memory": self.section_config.memory_chunk_size,
        }
        return mapping.get(section_type, 10)

    def get_max_tokens(self, section_type: str) -> int:
        mapping = {
            "behavior": self.section_config.behavior_max_tokens,
            "strings": self.section_config.strings_max_tokens,
            "memory": self.section_config.memory_max_tokens,
        }
        return mapping.get(section_type, 5000)
