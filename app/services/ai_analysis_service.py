import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from app.config.ai_analysis_config import AIAnalysisConfig
from app.services.section_analysis_service import SectionAnalyzer
from app.utils.json_extractor import JSONExtractor


class AIAnalysisService:
    def __init__(self, model_service, parser_service, chunking_service):
        self.model_service = model_service
        self.parser_service = parser_service
        self.chunking_service = chunking_service
        self.json_extractor = JSONExtractor()
        self.section_analyzer = SectionAnalyzer(
            model_service, chunking_service, self.json_extractor
        )
        self.templates_dir = Path("app/templates/section_prompts")
        self.analysis_config = AIAnalysisConfig.get_config()

    async def analyze(
        self, parsed_results: Dict, model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        analysis_id = self._generate_analysis_id()

        print(f"Starting AI analysis: {analysis_id}")

        chunking_summary = self.chunking_service.analyze_chunking_requirements(
            parsed_results
        )

        analyses = {}
        model_usage = {}

        sorted_sections = sorted(self.analysis_config, key=lambda x: x["priority"])

        for section_config in sorted_sections:
            section_name = section_config["section"]
            print(f"Analyzing: {section_name}")

            result = await self.section_analyzer.analyze_section(
                section_config, parsed_results, analyses, model_name, analysis_id
            )

            if "ai_model" in result:
                model = result["ai_model"]
                model_usage[model] = model_usage.get(model, 0) + 1

            analyses[section_name] = result

            await asyncio.sleep(2)

        print(f"Analysis completed: {analysis_id}")

        return {
            "analysis_id": analysis_id,
            "timestamp": datetime.now().isoformat(),
            "sections_analyzed": list(analyses.keys()),
            "model_usage": model_usage,
            "chunking_summary": chunking_summary,
            "results": analyses,
        }

    def _generate_analysis_id(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = uuid.uuid4().hex[:8]
        return f"analysis_{timestamp}_{unique_id}"


async def get_ai_analysis_service(model_service, parser_service, chunking_service):
    return AIAnalysisService(model_service, parser_service, chunking_service)
