from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class SectionType(Enum):
    BEHAVIOR = "behavior"
    STRINGS = "strings"
    MEMORY = "memory"


@dataclass
class ChunkConfig:
    chunk_size: int
    max_tokens_estimate: int


@dataclass
class ChunkInfo:
    current_chunk: int
    total_chunks: int
    items_in_chunk: int
    estimated_tokens: int
    chunk_size_config: int
    additional_metrics: Optional[Dict[str, Any]] = None


@dataclass
class ChunkedData:
    data: Dict[str, Any]
    chunk_info: ChunkInfo


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
