from typing import Dict, List


class AIAnalysisConfig:
    @staticmethod
    def get_config() -> List[Dict]:
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
                "requires_previous": True,
                "chunkable": False,
                "priority": 2,
            },
            {
                "section": "memory_analysis",
                "prompt_file": "memory_analysis_prompt.txt",
                "input_sections": ["memory"],
                "requires_previous": True,
                "chunkable": True,
                "priority": 3,
            },
            {
                "section": "signatures_analysis",
                "prompt_file": "signatures_analysis_prompt.txt",
                "input_sections": ["signatures"],
                "requires_previous": True,
                "chunkable": False,
                "priority": 4,
            },
            {
                "section": "behavior_analysis",
                "prompt_file": "behavior_analysis_initial_prompt.txt",
                "continuation_prompt": "behavior_analysis_continuation_prompt.txt",
                "input_sections": ["behavior"],
                "requires_previous": True,
                "chunkable": True,
                "priority": 5,
            },
            {
                "section": "strings_analysis",
                "prompt_file": "strings_analysis_initial_prompt.txt",
                "input_sections": ["strings"],
                "requires_previous": True,
                "chunkable": True,
                "priority": 6,
            },
            {
                "section": "final_synthesis",
                "prompt_file": "final_synthesis_prompt.txt",
                "input_sections": ["all_ai_analyses"],
                "requires_previous": True,
                "chunkable": False,
                "priority": 7,
            },
        ]
