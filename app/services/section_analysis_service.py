import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class SectionAnalyzer:
    def __init__(self, model_service, chunking_service, json_extractor):
        self.model_service = model_service
        self.chunking_service = chunking_service
        self.json_extractor = json_extractor
        self.templates_dir = Path("app/templates/section_prompts")

    async def analyze_section(
        self,
        section_config: Dict,
        parsed_results: Dict,
        previous_analyses: Dict,
        model_name: Optional[str],
        analysis_id: str,
    ) -> Dict[str, Any]:
        try:
            prompt_template = await self._load_prompt(section_config["prompt_file"])
            input_data = self._prepare_input_data(
                parsed_results, section_config["input_sections"]
            )
            context = self._build_context(previous_analyses, section_config)

            if section_config.get("chunkable") and self._has_section_data(
                parsed_results, section_config
            ):
                return await self._analyze_chunked(
                    section_config,
                    parsed_results,
                    previous_analyses,
                    prompt_template,
                    context,
                    model_name,
                    analysis_id,
                )
            else:
                return await self._analyze_standard(
                    section_config,
                    prompt_template,
                    input_data,
                    context,
                    model_name,
                    analysis_id,
                )
        except Exception as e:
            print(f"Analysis failed for {section_config['section']}: {str(e)}")
            import traceback

            traceback.print_exc()
            return {
                "section": section_config["section"],
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "status": "failed",
            }

    async def _analyze_chunked(
        self,
        section_config: Dict,
        parsed_results: Dict,
        previous_analyses: Dict,
        prompt_template: str,
        context: str,
        model_name: Optional[str],
        analysis_id: str,
    ) -> Dict[str, Any]:
        section_name = section_config["section"]
        section_data = parsed_results["sections"][section_config["input_sections"][0]]

        chunked_data_list = self._get_chunks(section_name, section_data)

        continuation_prompt_filename = section_config.get("continuation_prompt")
        continuation_prompt = (
            await self._load_prompt(continuation_prompt_filename)
            if continuation_prompt_filename
            else None
        )

        print(f"Processing {len(chunked_data_list)} chunks for {section_name}")

        # ✅ NEW: Parallel chunk processing
        enable_parallel_chunks = section_config.get("parallel_chunks", True)
        max_parallel_chunks = section_config.get("max_parallel_chunks", 3)

        if enable_parallel_chunks and len(chunked_data_list) > 1:
            chunk_results = await self._process_chunks_parallel(
                chunked_data_list,
                section_name,
                prompt_template,
                continuation_prompt,
                context,
                model_name,
                analysis_id,
                max_parallel_chunks,
            )
        else:
            chunk_results = await self._process_chunks_sequential(
                chunked_data_list,
                section_name,
                prompt_template,
                continuation_prompt,
                context,
                model_name,
                analysis_id,
            )

        return {
            "section": section_name,
            "type": "chunked",
            "total_chunks": len(chunked_data_list),
            "chunks_analyzed": len([c for c in chunk_results if "analysis" in c]),
            "chunks_failed": len([c for c in chunk_results if "error" in c]),
            "chunk_results": chunk_results,
            "combined_analysis": self._combine_chunks(chunk_results),
            "timestamp": datetime.now().isoformat(),
        }

    async def _process_chunks_parallel(
        self,
        chunked_data_list: List,
        section_name: str,
        prompt_template: str,
        continuation_prompt: Optional[str],
        context: str,
        model_name: Optional[str],
        analysis_id: str,
        max_parallel: int,
    ) -> List[Dict[str, Any]]:
        """Process chunks in parallel."""
        print(f"  → Using parallel processing (max {max_parallel} concurrent)")

        semaphore = asyncio.Semaphore(max_parallel)

        async def process_single_chunk(idx: int, chunked_data):
            async with semaphore:
                chunk_info_dict = {
                    "current_chunk": chunked_data.chunk_info.current_chunk,
                    "total_chunks": chunked_data.chunk_info.total_chunks,
                    "items_in_chunk": chunked_data.chunk_info.items_in_chunk,
                    "estimated_tokens": chunked_data.chunk_info.estimated_tokens,
                }

                if chunked_data.chunk_info.additional_metrics:
                    chunk_info_dict.update(chunked_data.chunk_info.additional_metrics)

                # Use initial prompt for all chunks in parallel mode
                full_prompt = self._build_prompt(
                    prompt_template,
                    context,
                    chunked_data.data,
                    chunk_info_dict,
                    section_name,
                )

                task_id = f"{section_name}_chunk_{chunk_info_dict['current_chunk']}"

                try:
                    result = await self._call_with_fallback(
                        full_prompt, model_name, analysis_id, task_id
                    )

                    analysis = self.json_extractor.extract(result.get("response", ""))

                    return {
                        "chunk_number": chunk_info_dict["current_chunk"],
                        "total_chunks": chunk_info_dict["total_chunks"],
                        "chunk_info": chunk_info_dict,
                        "analysis": analysis,
                        "ai_model": result.get("model"),
                        "api_key_index": result.get("api_key_index"),
                        "timestamp": datetime.now().isoformat(),
                    }

                except Exception as e:
                    print(
                        f"  ✗ Chunk {chunk_info_dict['current_chunk']} failed: {str(e)}"
                    )
                    return {
                        "chunk_number": chunk_info_dict["current_chunk"],
                        "total_chunks": chunk_info_dict["total_chunks"],
                        "error": str(e),
                        "timestamp": datetime.now().isoformat(),
                    }

        # Process all chunks in parallel
        tasks = [
            process_single_chunk(idx, chunk)
            for idx, chunk in enumerate(chunked_data_list)
        ]
        chunk_results = await asyncio.gather(*tasks)

        # Sort by chunk number to maintain order
        chunk_results = sorted(chunk_results, key=lambda x: x.get("chunk_number", 0))

        return chunk_results

    async def _process_chunks_sequential(
        self,
        chunked_data_list: List,
        section_name: str,
        prompt_template: str,
        continuation_prompt: Optional[str],
        context: str,
        model_name: Optional[str],
        analysis_id: str,
    ) -> List[Dict[str, Any]]:
        """Process chunks sequentially (original method)."""
        print("  → Using sequential processing")

        chunk_results = []
        previous_chunk = None

        for idx, chunked_data in enumerate(chunked_data_list):
            chunk_info_dict = {
                "current_chunk": chunked_data.chunk_info.current_chunk,
                "total_chunks": chunked_data.chunk_info.total_chunks,
                "items_in_chunk": chunked_data.chunk_info.items_in_chunk,
                "estimated_tokens": chunked_data.chunk_info.estimated_tokens,
            }

            if chunked_data.chunk_info.additional_metrics:
                chunk_info_dict.update(chunked_data.chunk_info.additional_metrics)

            current_prompt = (
                continuation_prompt
                if continuation_prompt and idx > 0
                else prompt_template
            )
            chunk_context = (
                self._build_chunk_context(previous_chunk, context)
                if idx > 0
                else context
            )

            full_prompt = self._build_prompt(
                current_prompt,
                chunk_context,
                chunked_data.data,
                chunk_info_dict,
                section_name,
            )

            try:
                result = await self._call_with_fallback(
                    full_prompt,
                    model_name,
                    analysis_id,
                    f"{section_name}_chunk_{chunk_info_dict['current_chunk']}",
                )

                analysis = self.json_extractor.extract(result.get("response", ""))

                chunk_result = {
                    "chunk_number": chunk_info_dict["current_chunk"],
                    "total_chunks": chunk_info_dict["total_chunks"],
                    "chunk_info": chunk_info_dict,
                    "analysis": analysis,
                    "ai_model": result.get("model"),
                    "api_key_index": result.get("api_key_index"),
                    "timestamp": datetime.now().isoformat(),
                }

                chunk_results.append(chunk_result)
                previous_chunk = chunk_result

                if idx < len(chunked_data_list) - 1:
                    await asyncio.sleep(1)

            except Exception as e:
                print(f"Chunk {chunk_info_dict['current_chunk']} failed: {str(e)}")
                import traceback

                traceback.print_exc()
                chunk_results.append(
                    {
                        "chunk_number": chunk_info_dict["current_chunk"],
                        "total_chunks": chunk_info_dict["total_chunks"],
                        "error": str(e),
                        "timestamp": datetime.now().isoformat(),
                    }
                )

        return chunk_results

    async def _analyze_standard(
        self,
        section_config: Dict,
        prompt_template: str,
        input_data: str,
        context: str,
        model_name: Optional[str],
        analysis_id: str,
    ) -> Dict[str, Any]:
        full_prompt = (
            f"{prompt_template}\n\n{context}\n\nANALYSIS DATA:\n{input_data}"
            if context
            else f"{prompt_template}\n\nANALYSIS DATA:\n{input_data}"
        )

        try:
            result = await self._call_with_fallback(
                full_prompt, model_name, analysis_id, section_config["section"]
            )

            analysis = self.json_extractor.extract(result.get("response", ""))

            return {
                "section": section_config["section"],
                "type": "standard",
                "ai_model": result.get("model"),
                "api_key_index": result.get("api_key_index"),
                "analysis": analysis,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            raise Exception(f"Standard analysis failed: {str(e)}") from e

    async def _call_with_fallback(
        self,
        prompt: str,
        preferred_model: Optional[str],
        analysis_id: str,
        section_name: str,
    ) -> Dict[str, Any]:
        models = self._get_model_priority(preferred_model)

        last_error = None
        for model_name in models:
            try:
                # ✅ NEW: Pass task_id for parallel tracking
                result = await self.model_service.process_request(
                    prompt=prompt, model_name=model_name, task_id=section_name
                )

                if result.get("response") and len(result["response"].strip()) > 50:
                    return result
                else:
                    raise Exception("Invalid or empty response")

            except Exception as e:
                last_error = e
                error_msg = str(e).lower()

                if any(keyword in error_msg for keyword in ["rate", "quota", "429"]):
                    await asyncio.sleep(3)

                continue

        raise Exception(f"All models failed. Last error: {last_error}")

    def _get_model_priority(self, preferred_model: Optional[str]) -> List[str]:
        models = []
        if preferred_model:
            models.append(preferred_model)

        if hasattr(self.model_service, "fallback_priority"):
            models.extend(
                [m for m in self.model_service.fallback_priority if m not in models]
            )
        else:
            models.extend(
                ["gemini-2.5-flash", "grok-4.1-fast-free", "llama-3.3-70b-free"]
            )

        return models

    async def _load_prompt(self, filename: str) -> str:
        path = self.templates_dir / filename
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            raise Exception(f"Failed to load prompt {filename}: {str(e)}") from e

    def _prepare_input_data(
        self, parsed_results: Dict, section_names: List[str]
    ) -> str:
        if section_names == ["all"]:
            return json.dumps(parsed_results["sections"], indent=2)
        elif section_names == ["all_ai_analyses"]:
            return ""
        else:
            data = {
                name: parsed_results["sections"].get(name)
                for name in section_names
                if name in parsed_results["sections"]
            }
            return json.dumps(data, indent=2)

    def _build_context(self, previous_analyses: Dict, section_config: Dict) -> str:
        if not section_config.get("requires_previous") or not previous_analyses:
            return ""

        if section_config["section"] == "final_synthesis":
            return "PREVIOUS AI ANALYSES:\n" + json.dumps(
                previous_analyses, indent=2, default=str
            )

        context_data = {
            name: analysis.get("analysis")
            for name, analysis in previous_analyses.items()
            if "analysis" in analysis
        }
        return (
            "ANALYSIS CONTEXT:\n" + json.dumps(context_data, indent=2, default=str)
            if context_data
            else ""
        )

    def _build_chunk_context(
        self, previous_chunk: Optional[Dict[str, Any]], base_context: str
    ) -> str:
        if not previous_chunk:
            return base_context

        return "CONTINUATION CONTEXT:\n" + json.dumps(
            {
                "previous_chunk_analysis": previous_chunk.get("analysis", {}),
                "base_context": base_context,
            },
            indent=2,
            default=str,
        )

    def _build_prompt(
        self,
        template: str,
        context: str,
        chunk_data: Dict,
        chunk_info: Dict,
        section_name: str,
    ) -> str:
        prompt = template.replace("{chunk_info}", json.dumps(chunk_info, indent=2))
        prompt = prompt.replace("{section_data}", json.dumps(chunk_data, indent=2))

        return f"{prompt}\n\n{context}" if context else prompt

    def _get_chunks(self, section_name: str, section_data: Dict) -> List:
        """Get chunks for a section. Returns list of ChunkedData objects."""
        if section_name == "behavior_analysis":
            return self.chunking_service.chunk_behavior_data(section_data)
        elif section_name == "strings_analysis":
            return self.chunking_service.chunk_strings_data(section_data)
        elif section_name == "memory_analysis":
            return self.chunking_service.chunk_memory_data(section_data)
        else:
            from dataclasses import dataclass
            from typing import Any

            @dataclass
            class SimpleChunkInfo:
                current_chunk: int = 1
                total_chunks: int = 1
                items_in_chunk: int = 1
                estimated_tokens: int = 0
                additional_metrics: Optional[dict] = None

            @dataclass
            class SimpleChunkedData:
                data: Any
                chunk_info: SimpleChunkInfo

            return [SimpleChunkedData(data=section_data, chunk_info=SimpleChunkInfo())]

    def _has_section_data(self, parsed_results: Dict, section_config: Dict) -> bool:
        return section_config["input_sections"][0] in parsed_results["sections"]

    def _combine_chunks(self, chunk_results: List[Dict]) -> Dict[str, Any]:
        """Combine analysis results from multiple chunks into a summary."""
        successful = [c for c in chunk_results if "analysis" in c]

        if not successful:
            return {"error": "All chunks failed", "total_chunks": len(chunk_results)}

        combined = {
            "total_chunks_processed": len(successful),
            "chunks_failed": len(chunk_results) - len(successful),
            "summary": f"Analyzed {len(successful)} of {len(chunk_results)} chunks successfully",
        }

        if successful:
            combined["chunks_summary"] = [
                {
                    "chunk_number": c["chunk_number"],
                    "has_analysis": "analysis" in c,
                    "model": c.get("ai_model", "unknown"),
                    "api_key": c.get("api_key_index"),
                }
                for c in chunk_results
            ]

        return combined
