# app/config/ai_analysis_config.py

from typing import Dict, List


class AIAnalysisConfig:
    """Configuration for AI analysis sections and their processing order."""

    @staticmethod
    def get_config() -> List[Dict]:
        """
        Returns the configuration for all analysis sections.

        """
        return [
            {
                "section": "initial_combined_analysis",
                "prompt_file": "initial_combined_analysis_prompt.txt",
                "input_sections": ["info", "statistics", "cape"],
                "requires_previous": False,
                "chunkable": False,
                "priority": 1,
            },
            {
                "section": "target_analysis",
                "prompt_file": "target_analysis_prompt.txt",
                "input_sections": ["target"],
                "requires_previous": False,
                "chunkable": False,
                "priority": 1,
            },
            {
                "section": "signatures_analysis",
                "prompt_file": "signatures_analysis_prompt.txt",
                "input_sections": ["signatures"],
                "requires_previous": False,
                "chunkable": False,
                "priority": 1,
            },
            {
                "section": "memory_analysis",
                "prompt_file": "memory_analysis_prompt.txt",
                "input_sections": ["memory"],
                "requires_previous": False,
                "chunkable": False,
                "parallel_chunks": False,
                "max_parallel_chunks": 3,
                "priority": 2,
            },
            {
                "section": "behavior_analysis",
                "prompt_file": "behavior_analysis_initial_prompt.txt",
                # "continuation_prompt": "behavior_analysis_continuation_prompt.txt",
                "input_sections": ["behavior"],
                "requires_previous": False,
                "chunkable": False,
                "parallel_chunks": False,
                "max_parallel_chunks": 3,
                "priority": 2,
            },
            # {
            #     "section": "strings_analysis",
            #     "prompt_file": "strings_analysis_initial_prompt.txt",
            #     "input_sections": ["strings"],
            #     "requires_previous": False,
            #     "chunkable": True,
            #     "parallel_chunks": True,
            #     "max_parallel_chunks": 3,
            #     "priority": 2,
            # },
            {
                "section": "final_synthesis",
                "prompt_file": "final_synthesis_prompt.txt",
                "input_sections": ["all_ai_analyses"],
                "requires_previous": True,
                "chunkable": False,
                "priority": 3,
            },
        ]

    @staticmethod
    def get_section_config(section_name: str) -> Dict:
        """Get configuration for a specific section."""
        config = AIAnalysisConfig.get_config()
        for section in config:
            if section["section"] == section_name:
                return section
        raise ValueError(f"Section {section_name} not found in config")

    @staticmethod
    def get_sections_by_priority(priority: int) -> List[Dict]:
        """Get all sections with a specific priority."""
        config = AIAnalysisConfig.get_config()
        return [s for s in config if s.get("priority") == priority]

    @staticmethod
    def get_independent_sections() -> List[Dict]:
        """Get all sections that don't require previous analyses."""
        config = AIAnalysisConfig.get_config()
        return [s for s in config if not s.get("requires_previous", False)]

    @staticmethod
    def get_dependent_sections() -> List[Dict]:
        """Get all sections that require previous analyses."""
        config = AIAnalysisConfig.get_config()
        return [s for s in config if s.get("requires_previous", False)]

    @staticmethod
    def get_chunkable_sections() -> List[Dict]:
        """Get all sections that support chunking."""
        config = AIAnalysisConfig.get_config()
        return [s for s in config if s.get("chunkable", False)]
