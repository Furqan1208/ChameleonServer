import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

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
        self,
        parsed_results: Dict,
        model_name: Optional[str] = None,
        enable_parallel: bool = True,
        max_parallel_sections: int = 4,
        threat_intel_context: Optional[Dict] = None,  # ✅ NEW PARAMETER
    ) -> Dict[str, Any]:
        """
        Perform full malware analysis with optional parallel processing.

        Args:
            parsed_results: Parsed CAPE report data
            model_name: Preferred AI model
            enable_parallel: Enable parallel section processing
            max_parallel_sections: Max sections to process simultaneously
            threat_intel_context: Threat intelligence results for contextual analysis  # ✅ NEW
        """
        analysis_id = self._generate_analysis_id()

        print(f"Starting AI analysis: {analysis_id}")
        if enable_parallel:
            print(f"⚡ Parallel mode enabled (max {max_parallel_sections} sections)")
        else:
            print("🔄 Sequential mode")

        # ✅ Log threat intel status
        if threat_intel_context:
            print(
                f"🔍 Threat Intel context available: "
                f"{threat_intel_context.get('summary_line', 'Summary unavailable')}"
            )
        else:
            print("⚠️  No threat intel context provided - AI may hallucinate scores")

        start_time = datetime.now()

        chunking_summary = self.chunking_service.analyze_chunking_requirements(
            parsed_results
        )

        if enable_parallel:
            analyses, model_usage = await self._analyze_parallel(
                parsed_results,
                model_name,
                analysis_id,
                max_parallel_sections,
                threat_intel_context,  # ✅ Pass through
            )
        else:
            analyses, model_usage = await self._analyze_sequential(
                parsed_results,
                model_name,
                analysis_id,
                threat_intel_context,  # ✅ Pass through
            )

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Get API key usage stats
        api_stats = self.model_service.get_api_key_stats()

        print(f"Analysis completed: {analysis_id}")
        print(f"⏱️  Duration: {duration:.2f} seconds")

        return {
            "analysis_id": analysis_id,
            "timestamp": datetime.now().isoformat(),
            "sections_analyzed": list(analyses.keys()),
            "model_usage": model_usage,
            "chunking_summary": chunking_summary,
            "duration_seconds": duration,
            "api_key_stats": api_stats,
            "threat_intel_used": threat_intel_context is not None,  # ✅ Include in response
            "results": analyses,
        }

    async def _analyze_parallel(
        self,
        parsed_results: Dict,
        model_name: Optional[str],
        analysis_id: str,
        max_parallel: int,
        threat_intel_context: Optional[Dict] = None,  # ✅ NEW PARAMETER
    ) -> tuple[Dict[str, Any], Dict[str, int]]:
        """Analyze sections in parallel where possible."""

        # Group sections by priority
        priority_groups = self._group_sections_by_priority()
        analyses = {}
        model_usage = {}

        for priority, sections in sorted(priority_groups.items()):
            # Check which sections have their dependencies met
            ready_sections = [
                s
                for s in sections
                if not s.get("requires_previous") or self._has_dependencies(s, analyses)
            ]

            if not ready_sections:
                continue

            print(
                f"\n📊 Processing priority {priority} ({len(ready_sections)} sections)"
            )

            # Process ready sections in parallel
            semaphore = asyncio.Semaphore(max_parallel)

            async def analyze_with_semaphore(config, semaphore=semaphore):
                async with semaphore:
                    section_name = config["section"]
                    print(f"  → Analyzing: {section_name}")

                    result = await self.section_analyzer.analyze_section(
                        section_config=config,
                        parsed_results=parsed_results,
                        previous_analyses=analyses,
                        model_name=model_name,
                        analysis_id=analysis_id,
                        threat_intel_context=threat_intel_context,  # ✅ Pass through
                    )

                    status = "✓" if "error" not in result else "✗"
                    print(f"  {status} Completed: {section_name}")

                    return section_name, result

            tasks = [analyze_with_semaphore(config) for config in ready_sections]
            section_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results and track model usage
            for item in section_results:
                if isinstance(item, BaseException):
                    print(f"  ✗ Section failed: {item}")
                else:
                    section_name, result = item
                    analyses[section_name] = result

                    # Track model usage
                    if "ai_model" in result:
                        model = result["ai_model"]
                        model_usage[model] = model_usage.get(model, 0) + 1

                    # Track chunked section models
                    if "chunk_results" in result:
                        for chunk in result["chunk_results"]:
                            if "ai_model" in chunk:
                                model = chunk["ai_model"]
                                model_usage[model] = model_usage.get(model, 0) + 1

            # Small delay between priority groups
            await asyncio.sleep(1)

        return analyses, model_usage

    async def _analyze_sequential(
        self,
        parsed_results: Dict,
        model_name: Optional[str],
        analysis_id: str,
        threat_intel_context: Optional[Dict] = None,  # ✅ NEW PARAMETER
    ) -> tuple[Dict[str, Any], Dict[str, int]]:
        """Original sequential analysis."""
        analyses = {}
        model_usage = {}

        sorted_sections = sorted(self.analysis_config, key=lambda x: x["priority"])

        for section_config in sorted_sections:
            section_name = section_config["section"]
            print(f"Analyzing: {section_name}")

            result = await self.section_analyzer.analyze_section(
                section_config=section_config,
                parsed_results=parsed_results,
                previous_analyses=analyses,
                model_name=model_name,
                analysis_id=analysis_id,
                threat_intel_context=threat_intel_context,  # ✅ Pass through
            )

            if "ai_model" in result:
                model = result["ai_model"]
                model_usage[model] = model_usage.get(model, 0) + 1

            # Track chunked section models
            if "chunk_results" in result:
                for chunk in result["chunk_results"]:
                    if "ai_model" in chunk:
                        model = chunk["ai_model"]
                        model_usage[model] = model_usage.get(model, 0) + 1

            analyses[section_name] = result
            await asyncio.sleep(2)

        return analyses, model_usage

    def _group_sections_by_priority(self) -> Dict[int, List[Dict]]:
        """Group sections by priority for parallel processing."""
        groups = {}
        for config in self.analysis_config:
            priority = config.get("priority", 99)
            if priority not in groups:
                groups[priority] = []
            groups[priority].append(config)
        return groups

    def _has_dependencies(self, section_config: Dict, analyses: Dict) -> bool:
        """Check if a section's dependencies are met."""
        if not section_config.get("requires_previous"):
            return True

        # For final_synthesis, need all other sections
        if section_config["section"] == "final_synthesis":
            required = [
                s["section"]
                for s in self.analysis_config
                if s["section"] != "final_synthesis"
            ]
            return all(req in analyses for req in required)

        return True

    def _generate_analysis_id(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = uuid.uuid4().hex[:8]
        return f"analysis_{timestamp}_{unique_id}"


async def get_ai_analysis_service(model_service, parser_service, chunking_service):
    return AIAnalysisService(model_service, parser_service, chunking_service)