import logging
import math
from typing import Any, Dict, List, Optional

from models import ChunkConfig, ChunkedData, ChunkInfo, SectionType
from utils import DataExtractor, TokenEstimator

logger = logging.getLogger(__name__)


class ChunkingService:
    def __init__(self):
        self.configs = {
            SectionType.BEHAVIOR: ChunkConfig(chunk_size=3, max_tokens_estimate=8000),
            SectionType.STRINGS: ChunkConfig(chunk_size=2000, max_tokens_estimate=6000),
            SectionType.MEMORY: ChunkConfig(chunk_size=10, max_tokens_estimate=4000),
        }
        self.extractor = DataExtractor()
        self.estimator = TokenEstimator()

    def chunk_behavior_data(
        self, behavior_data: Dict[str, Any], chunk_size: Optional[int] = None
    ) -> List[ChunkedData]:
        actual_data = self.extractor.extract_behavior_data(behavior_data)
        config = self.configs[SectionType.BEHAVIOR]
        chunk_size = chunk_size or config.chunk_size

        processes = actual_data.get("processes", [])

        if not processes:
            return self._create_empty_chunk(
                actual_data, chunk_size, {"api_calls_in_chunk": 0}
            )

        total_chunks = math.ceil(len(processes) / chunk_size)
        chunks = []

        for chunk_idx in range(total_chunks):
            start_idx = chunk_idx * chunk_size
            end_idx = min((chunk_idx + 1) * chunk_size, len(processes))
            chunk_processes = processes[start_idx:end_idx]

            api_calls_count = sum(
                len(proc.get("calls", [])) for proc in chunk_processes
            )

            chunk_pids = {str(proc.get("process_id")) for proc in chunk_processes}

            chunk_data = {
                "processes": chunk_processes,
                "summary": actual_data.get("summary"),
                "anomaly": actual_data.get("anomaly", []),
                "processtree": self.extractor.filter_processtree(
                    actual_data.get("processtree", []), chunk_pids
                ),
                "enhanced": actual_data.get("enhanced", []),
                "encryptedbuffers": actual_data.get("encryptedbuffers", []),
            }

            estimated_tokens = self.estimator.estimate_behavior_tokens(chunk_data)

            chunk_info = ChunkInfo(
                current_chunk=chunk_idx + 1,
                total_chunks=total_chunks,
                items_in_chunk=len(chunk_processes),
                estimated_tokens=estimated_tokens,
                chunk_size_config=chunk_size,
                additional_metrics={"api_calls": api_calls_count},
            )

            chunks.append(ChunkedData(data=chunk_data, chunk_info=chunk_info))

        logger.info(
            f"Chunked behavior data into {total_chunks} chunks "
            f"({len(processes)} processes)"
        )

        return chunks

    def chunk_strings_data(
        self, strings_data: Dict[str, Any], chunk_size: Optional[int] = None
    ) -> List[ChunkedData]:
        actual_data = self.extractor.extract_strings_data(strings_data)
        config = self.configs[SectionType.STRINGS]
        chunk_size = chunk_size or config.chunk_size

        categories = actual_data.get("categories", {})
        all_strings = [
            (category, string)
            for category, strings in categories.items()
            for string in strings
        ]

        if not all_strings:
            return self._create_empty_chunk(actual_data, chunk_size, {})

        total_chunks = math.ceil(len(all_strings) / chunk_size)
        chunks = []

        for chunk_idx in range(total_chunks):
            start_idx = chunk_idx * chunk_size
            end_idx = min((chunk_idx + 1) * chunk_size, len(all_strings))
            chunk_strings = all_strings[start_idx:end_idx]

            chunk_categories = {}
            for category, string in chunk_strings:
                chunk_categories.setdefault(category, []).append(string)

            chunk_data = {
                "categories": chunk_categories,
                "metadata": actual_data.get("metadata", {}),
            }

            estimated_tokens = self.estimator.estimate_strings_tokens(chunk_data)

            chunk_info = ChunkInfo(
                current_chunk=chunk_idx + 1,
                total_chunks=total_chunks,
                items_in_chunk=len(chunk_strings),
                estimated_tokens=estimated_tokens,
                chunk_size_config=chunk_size,
                additional_metrics={"categories": list(chunk_categories.keys())},
            )

            chunks.append(ChunkedData(data=chunk_data, chunk_info=chunk_info))

        logger.info(
            f"Chunked strings data into {total_chunks} chunks "
            f"({len(all_strings)} strings)"
        )

        return chunks

    def chunk_memory_data(
        self, memory_data: Dict[str, Any], chunk_size: Optional[int] = None
    ) -> List[ChunkedData]:
        actual_data = self.extractor.extract_memory_data(memory_data)
        config = self.configs[SectionType.MEMORY]
        chunk_size = chunk_size or config.chunk_size

        procmemory = actual_data.get("procmemory", [])

        if not procmemory:
            return self._create_empty_chunk(actual_data, chunk_size, {})

        total_chunks = math.ceil(len(procmemory) / chunk_size)
        chunks = []

        for chunk_idx in range(total_chunks):
            start_idx = chunk_idx * chunk_size
            end_idx = min((chunk_idx + 1) * chunk_size, len(procmemory))
            chunk_entries = procmemory[start_idx:end_idx]

            chunk_data = {
                "procmemory": chunk_entries,
                "metadata": actual_data.get("metadata", {}),
            }

            estimated_tokens = self.estimator.estimate_memory_tokens(chunk_data)

            chunk_info = ChunkInfo(
                current_chunk=chunk_idx + 1,
                total_chunks=total_chunks,
                items_in_chunk=len(chunk_entries),
                estimated_tokens=estimated_tokens,
                chunk_size_config=chunk_size,
            )

            chunks.append(ChunkedData(data=chunk_data, chunk_info=chunk_info))

        logger.info(
            f"Chunked memory data into {total_chunks} chunks "
            f"({len(procmemory)} entries)"
        )

        return chunks

    def analyze_chunking_requirements(
        self, parsed_results: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        analysis = {}
        sections = parsed_results.get("sections", {})

        for section_name, section_data in sections.items():
            try:
                section_type = SectionType(section_name)
            except ValueError:
                continue

            config = self.configs[section_type]

            if section_type == SectionType.BEHAVIOR:
                analysis[section_name] = self._analyze_behavior(section_data, config)
            elif section_type == SectionType.STRINGS:
                analysis[section_name] = self._analyze_strings(section_data, config)
            elif section_type == SectionType.MEMORY:
                analysis[section_name] = self._analyze_memory(section_data, config)

        logger.info(f"Analyzed chunking requirements for {len(analysis)} sections")
        return analysis

    def _analyze_behavior(
        self, data: Dict[str, Any], config: ChunkConfig
    ) -> Dict[str, Any]:
        actual_data = self.extractor.extract_behavior_data(data)
        processes = actual_data.get("processes", [])
        process_count = len(processes)

        api_call_count = sum(len(proc.get("calls", [])) for proc in processes)

        chunks_needed = max(1, math.ceil(process_count / config.chunk_size))

        return {
            "needs_chunking": process_count > config.chunk_size,
            "process_count": process_count,
            "api_call_count": api_call_count,
            "estimated_chunks": chunks_needed,
            "recommended_chunk_size": config.chunk_size,
        }

    def _analyze_strings(
        self, data: Dict[str, Any], config: ChunkConfig
    ) -> Dict[str, Any]:
        actual_data = self.extractor.extract_strings_data(data)
        categories = actual_data.get("categories", {})

        total_strings = sum(len(strings) for strings in categories.values())
        chunks_needed = max(1, math.ceil(total_strings / config.chunk_size))

        return {
            "needs_chunking": total_strings > config.chunk_size,
            "total_strings": total_strings,
            "category_count": len(categories),
            "estimated_chunks": chunks_needed,
            "recommended_chunk_size": config.chunk_size,
        }

    def _analyze_memory(
        self, data: Dict[str, Any], config: ChunkConfig
    ) -> Dict[str, Any]:
        actual_data = self.extractor.extract_memory_data(data)
        procmemory = actual_data.get("procmemory", [])
        entry_count = len(procmemory)

        chunks_needed = max(1, math.ceil(entry_count / config.chunk_size))

        return {
            "needs_chunking": entry_count > config.chunk_size,
            "entry_count": entry_count,
            "estimated_chunks": chunks_needed,
            "recommended_chunk_size": config.chunk_size,
        }

    def _create_empty_chunk(
        self, data: Dict[str, Any], chunk_size: int, additional_metrics: Dict[str, Any]
    ) -> List[ChunkedData]:
        chunk_info = ChunkInfo(
            current_chunk=1,
            total_chunks=1,
            items_in_chunk=0,
            estimated_tokens=0,
            chunk_size_config=chunk_size,
            additional_metrics=additional_metrics,
        )

        return [ChunkedData(data=data, chunk_info=chunk_info)]


async def get_chunking_service() -> ChunkingService:
    return ChunkingService()
