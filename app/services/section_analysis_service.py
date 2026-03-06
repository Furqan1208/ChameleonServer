import asyncio
import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class SectionAnalyzer:
    def __init__(
        self, model_service, chunking_service, json_extractor, analysis_id: str = None
    ):
        self.model_service = model_service
        self.chunking_service = chunking_service
        self.json_extractor = json_extractor
        self.templates_dir = Path("app/templates/section_prompts")

        # Setup logging
        self.analysis_id = analysis_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self._setup_logging()

        self.logger = logging.getLogger(f"SectionAnalyzer.{self.analysis_id[:8]}")
        self.logger.info(
            f"Initialized SectionAnalyzer for analysis: {self.analysis_id}"
        )

    def _setup_logging(self):
        """Setup comprehensive logging to file and console."""
        # Create logs directory if it doesn't exist
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)

        # Create a unique logger for this analysis
        logger_name = f"section_analyzer_{self.analysis_id}"
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.DEBUG)

        # Clear existing handlers
        logger.handlers.clear()

        # File handler for detailed logs
        log_file = logs_dir / f"analysis_{self.analysis_id}.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        self.logger = logger

    async def analyze_section(
        self,
        section_config: Dict,
        parsed_results: Dict,
        previous_analyses: Dict,
        model_name: Optional[str],
        analysis_id: str,
    ) -> Dict[str, Any]:
        """Analyze a specific section using AI."""
        section_name = section_config.get("section")
        self.logger.info(f"Starting analysis for section: {section_name}")

        # ✅ Check if this is strings analysis - skip it
        if section_name == "strings_analysis":
            self.logger.warning("Skipping strings analysis as requested")
            return {
                "section": "strings_analysis",
                "type": "skipped",
                "status": "skipped",
                "note": "Strings analysis disabled as per configuration",
                "timestamp": datetime.now().isoformat(),
            }

        try:
            prompt_template = await self._load_prompt(section_config["prompt_file"])
            input_data = self._prepare_input_data(
                parsed_results, section_config["input_sections"]
            )

            # ✅ Get context for this section
            context = self._build_context(
                previous_analyses, section_config, section_name
            )

            # ✅ SPECIAL LOGGING FOR FINAL SYNTHESIS
            if section_name == "final_synthesis":
                self._log_final_synthesis_context(
                    previous_analyses, context, input_data
                )

            self.logger.debug(
                f"Section: {section_name}, Input sections: {section_config['input_sections']}"
            )
            self.logger.debug(
                f"Has section data: {self._has_section_data(parsed_results, section_config)}"
            )
            self.logger.debug(f"Is chunkable: {section_config.get('chunkable', False)}")

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
            self.logger.error(
                f"Analysis failed for {section_name}: {str(e)}", exc_info=True
            )
            return {
                "section": section_name,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "status": "failed",
            }

    def _log_final_synthesis_context(
        self, previous_analyses: Dict, context: str, input_data: str
    ):
        """Special logging for final synthesis to debug context issues."""
        self.logger.info("=" * 80)
        self.logger.info("FINAL SYNTHESIS DEBUG LOGGING")
        self.logger.info("=" * 80)

        # Log previous analyses structure
        self.logger.info(f"Previous analyses count: {len(previous_analyses)}")
        for section, analysis in previous_analyses.items():
            self.logger.info(f"  - {section}:")
            if isinstance(analysis, dict):
                self.logger.info(f"    Type: {analysis.get('type', 'unknown')}")
                self.logger.info(f"    Status: {analysis.get('status', 'unknown')}")
                self.logger.info(
                    f"    Timestamp: {analysis.get('timestamp', 'unknown')}"
                )

                # Check if analysis has actual analysis content
                if "analysis" in analysis:
                    analysis_data = analysis["analysis"]
                    if isinstance(analysis_data, dict):
                        self.logger.info(
                            f"    Analysis keys: {list(analysis_data.keys())}"
                        )
                    else:
                        self.logger.warning(
                            f"    Analysis is not a dict: {type(analysis_data)}"
                        )
                else:
                    self.logger.warning(f"    No 'analysis' key in {section}!")
            else:
                self.logger.warning(f"    Analysis is not a dict: {type(analysis)}")

        # Log context size and preview
        self.logger.info(f"Context size: {len(context)} characters")
        if len(context) > 0:
            self.logger.info(f"Context preview (first 500 chars):")
            self.logger.info(context[:500] + "..." if len(context) > 500 else context)

        # Log input data size
        self.logger.info(f"Input data size: {len(input_data)} characters")

        # Save detailed context to file for inspection
        context_file = Path(f"logs/final_synthesis_context_{self.analysis_id}.json")
        try:
            context_data = {
                "previous_analyses": previous_analyses,
                "context_preview": context[:2000] + "..."
                if len(context) > 2000
                else context,
                "context_size": len(context),
                "input_data_size": len(input_data),
                "timestamp": datetime.now().isoformat(),
            }
            context_file.write_text(
                json.dumps(context_data, indent=2, default=str), encoding="utf-8"
            )
            self.logger.info(f"Saved detailed context to: {context_file}")
        except Exception as e:
            self.logger.error(f"Failed to save context file: {e}")

        self.logger.info("=" * 80)

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
        """Analyze section using chunking approach."""
        section_name = section_config["section"]
        self.logger.info(f"Starting chunked analysis for {section_name}")

        # ✅ Skip if this is strings analysis
        if section_name == "strings_analysis":
            self.logger.warning("Skipping strings analysis (chunked mode)")
            return {
                "section": "strings_analysis",
                "type": "skipped",
                "status": "skipped",
                "note": "Strings analysis disabled as per configuration",
                "timestamp": datetime.now().isoformat(),
            }

        section_data = parsed_results["sections"][section_config["input_sections"][0]]

        # Clean behavior data before chunking if needed
        if section_name == "behavior_analysis":
            section_data = self._clean_behavior_for_ai(section_data)

        chunked_data_list = self._get_chunks(section_name, section_data)

        continuation_prompt_filename = section_config.get("continuation_prompt")
        continuation_prompt = (
            await self._load_prompt(continuation_prompt_filename)
            if continuation_prompt_filename
            else None
        )

        self.logger.info(
            f"Processing {len(chunked_data_list)} chunks for {section_name}"
        )

        # ✅ Parallel chunk processing
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

        result = {
            "section": section_name,
            "type": "chunked",
            "total_chunks": len(chunked_data_list),
            "chunks_analyzed": len([c for c in chunk_results if "analysis" in c]),
            "chunks_failed": len([c for c in chunk_results if "error" in c]),
            "chunk_results": chunk_results,
            "combined_analysis": self._combine_chunks(chunk_results),
            "timestamp": datetime.now().isoformat(),
        }

        self.logger.info(
            f"Completed chunked analysis for {section_name}: "
            f"{result['chunks_analyzed']}/{result['total_chunks']} chunks successful"
        )

        return result

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
        self.logger.info(f"Using parallel processing (max {max_parallel} concurrent)")

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
                    self.logger.debug(
                        f"Processing chunk {chunk_info_dict['current_chunk']}/{chunk_info_dict['total_chunks']}"
                    )

                    result = await self._call_with_fallback(
                        full_prompt, model_name, analysis_id, section_name, task_id
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
                    self.logger.error(
                        f"Chunk {chunk_info_dict['current_chunk']} failed: {str(e)}"
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

        self.logger.info(
            f"Parallel processing completed: {len([c for c in chunk_results if 'analysis' in c])}/{len(chunk_results)} successful"
        )
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
        self.logger.info("Using sequential processing")

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
                self.logger.debug(
                    f"Processing chunk {chunk_info_dict['current_chunk']}/{chunk_info_dict['total_chunks']}"
                )

                result = await self._call_with_fallback(
                    full_prompt,
                    model_name,
                    analysis_id,
                    section_name,
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
                self.logger.error(
                    f"Chunk {chunk_info_dict['current_chunk']} failed: {str(e)}",
                    exc_info=True,
                )
                chunk_results.append(
                    {
                        "chunk_number": chunk_info_dict["current_chunk"],
                        "total_chunks": chunk_info_dict["total_chunks"],
                        "error": str(e),
                        "timestamp": datetime.now().isoformat(),
                    }
                )

        self.logger.info(
            f"Sequential processing completed: {len([c for c in chunk_results if 'analysis' in c])}/{len(chunk_results)} successful"
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
        """Analyze section using standard (non-chunked) approach."""
        section_name = section_config.get("section")
        self.logger.info(f"Starting standard analysis for {section_name}")

        # ✅ Skip if this is strings analysis
        if section_name == "strings_analysis":
            self.logger.warning("Skipping strings analysis (standard mode)")
            return {
                "section": "strings_analysis",
                "type": "skipped",
                "status": "skipped",
                "note": "Strings analysis disabled as per configuration",
                "timestamp": datetime.now().isoformat(),
            }

        # ✅ SPECIAL HANDLING FOR FINAL SYNTHESIS
        if section_name == "final_synthesis":
            self.logger.info("=== FINAL SYNTHESIS ANALYSIS START ===")
            self.logger.info(f"Context provided: {len(context)} characters")
            self.logger.info(f"Input data: {len(input_data)} characters")

            # Save the complete prompt for debugging
            full_prompt = self._build_final_synthesis_prompt(
                prompt_template, context, input_data
            )

            # Save prompt to file for inspection
            prompt_file = Path(f"logs/final_synthesis_prompt_{self.analysis_id}.txt")
            prompt_file.write_text(full_prompt, encoding="utf-8")
            self.logger.info(f"Saved final synthesis prompt to: {prompt_file}")

            # Log prompt summary
            self.logger.info(
                f"Final synthesis prompt size: {len(full_prompt)} characters"
            )

        else:
            # For other sections, use standard prompt building
            full_prompt = self._build_standard_prompt(
                section_name, prompt_template, input_data, context
            )

        try:
            if section_name == "final_synthesis":
                self.logger.info("Sending final synthesis to AI...")

            result = await self._call_with_fallback(
                full_prompt, model_name, analysis_id, section_name, section_name
            )

            # ✅ Check if response is complete
            if section_name in ["behavior_analysis", "final_synthesis"]:
                response = result.get("response", "")
                is_complete = self._check_response_completeness(response)

                if not is_complete:
                    self.logger.warning(
                        f"{section_name} response may be incomplete (length: {len(response)} chars)"
                    )
                    fixed_response = self._fix_incomplete_json(response)
                    if fixed_response != response:
                        self.logger.info(
                            f"Fixed incomplete JSON (original: {len(response)} chars, fixed: {len(fixed_response)} chars)"
                        )
                        result["response"] = fixed_response

            # ✅ SPECIAL EXTRACTION FOR FINAL SYNTHESIS
            if section_name == "final_synthesis":
                analysis = self._extract_final_synthesis(result.get("response", ""))
            else:
                analysis = self.json_extractor.extract(result.get("response", ""))

            # ✅ SPECIAL LOGGING FOR FINAL SYNTHESIS RESPONSE
            if section_name == "final_synthesis":
                self.logger.info("=== FINAL SYNTHESIS ANALYSIS COMPLETE ===")
                self.logger.info(f"AI Model used: {result.get('model')}")
                self.logger.info(
                    f"Response size: {len(result.get('response', ''))} characters"
                )
                self.logger.info(f"Extracted analysis type: {type(analysis)}")

                if isinstance(analysis, dict):
                    self.logger.info(
                        f"Analysis structure keys: {list(analysis.keys())}"
                    )

                    # Log key metrics
                    for key in [
                        "analysis_stage",
                        "cross_stage_correlation_analysis",
                        "integrated_threat_assessment",
                        "mitre_attack_integration",
                    ]:
                        if key in analysis:
                            self.logger.info(f"  - {key}: Present")

                    # Check if we got the full structure
                    if "cross_stage_correlation_analysis" in analysis:
                        correlation = analysis["cross_stage_correlation_analysis"]
                        if "evidence_convergence" in correlation:
                            convergence = correlation["evidence_convergence"]
                            if "strongly_correlated_findings" in convergence:
                                findings = convergence["strongly_correlated_findings"]
                                self.logger.info(f"  - Findings count: {len(findings)}")

                # Save the complete analysis
                analysis_file = Path(
                    f"logs/final_synthesis_complete_{self.analysis_id}.json"
                )
                analysis_file.write_text(
                    json.dumps(analysis, indent=2, default=str), encoding="utf-8"
                )
                self.logger.info(f"Saved complete analysis to: {analysis_file}")

            return {
                "section": section_name,
                "type": "standard",
                "ai_model": result.get("model"),
                "api_key_index": result.get("api_key_index"),
                "analysis": analysis,
                "timestamp": datetime.now().isoformat(),
                "status": "completed",
            }
        except Exception as e:
            self.logger.error(
                f"AI call failed for {section_name}: {str(e)}", exc_info=True
            )
            raise Exception(f"Standard analysis failed: {str(e)}") from e

    def _extract_final_synthesis(self, response: str) -> Dict[str, Any]:
        """
        Special extraction for final synthesis responses.
        Handles the full JSON structure instead of just extracting a subset.
        """
        try:
            # First try to extract JSON using the standard extractor
            extracted = self.json_extractor.extract(response)

            # If we get a dict with the expected structure, return it
            if isinstance(extracted, dict):
                self.logger.info(
                    f"Extracted final synthesis structure: {list(extracted.keys())}"
                )

                # Check if this looks like a minimal extraction or full structure
                minimal_keys = {
                    "finding_description",
                    "supporting_stages",
                    "evidence_types",
                    "convergence_strength",
                }
                full_keys = {
                    "analysis_stage",
                    "cross_stage_correlation_analysis",
                    "integrated_threat_assessment",
                }

                if minimal_keys.issubset(
                    set(extracted.keys())
                ) and not full_keys.issubset(set(extracted.keys())):
                    # This is the minimal extraction, we need to get the full response
                    self.logger.warning(
                        "Only minimal extraction found, attempting to extract full JSON"
                    )
                    return self._extract_full_final_synthesis(response)
                else:
                    # This looks like the full structure
                    return extracted

            # If extraction returned something else, try to get the full JSON
            return self._extract_full_final_synthesis(response)

        except Exception as e:
            self.logger.error(f"Error extracting final synthesis: {e}")
            return self._extract_full_final_synthesis(response)

    def _extract_full_final_synthesis(self, response: str) -> Dict[str, Any]:
        """
        Extract the complete final synthesis JSON from the response.
        """
        try:
            # Clean the response
            cleaned = response.strip()

            # Remove markdown code blocks
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)

            # Try to find JSON with regex
            json_pattern = r"\{.*\}"
            matches = re.findall(json_pattern, cleaned, re.DOTALL)

            if matches:
                # Try each match
                for match in matches:
                    try:
                        parsed = json.loads(match)
                        self.logger.info(f"Successfully parsed JSON from response")

                        # Ensure it has the expected structure
                        if isinstance(parsed, dict):
                            # Check if it's the minimal or full structure
                            minimal_keys = {
                                "finding_description",
                                "supporting_stages",
                                "evidence_types",
                                "convergence_strength",
                            }
                            if minimal_keys.issubset(set(parsed.keys())):
                                # This is a minimal finding, not the full synthesis
                                self.logger.warning(
                                    "Parsed JSON appears to be a minimal finding, not full synthesis"
                                )
                                continue

                            # Check for full synthesis structure
                            if (
                                "analysis_stage" in parsed
                                or "cross_stage_correlation_analysis" in parsed
                            ):
                                self.logger.info("Found full final synthesis structure")
                                return parsed

                    except json.JSONDecodeError:
                        continue

            # If we get here, try to parse the entire response as JSON
            try:
                parsed = json.loads(cleaned)
                self.logger.info("Parsed entire response as JSON")
                return parsed
            except json.JSONDecodeError:
                pass

            # Last resort: create a structured response from what we have
            self.logger.warning(
                "Could not parse full JSON, creating structured response"
            )
            return {
                "analysis_stage": "stage_6_final_threat_synthesis",
                "raw_response": response[:5000] + "..."
                if len(response) > 5000
                else response,
                "note": "Full JSON parsing failed, showing raw response",
                "response_length": len(response),
            }

        except Exception as e:
            self.logger.error(f"Failed to extract full final synthesis: {e}")
            return {
                "error": f"Failed to extract final synthesis: {str(e)}",
                "raw_response_preview": response[:1000]
                if response
                else "Empty response",
            }

    def _build_standard_prompt(
        self, section_name: str, prompt_template: str, input_data: str, context: str
    ) -> str:
        """Build standard prompt for non-final-synthesis sections."""
        if section_name == "behavior_analysis":
            try:
                behavior_data = json.loads(input_data) if input_data else {}
                self.logger.debug(
                    f"Behavior analysis - Raw behavior_data type: {type(behavior_data)}"
                )

                if "data" not in behavior_data:
                    self.logger.warning("'data' key not found in behavior_data!")
                    behavior_data = {"data": behavior_data}

                full_prompt = prompt_template

                if "{behavior_data}" in prompt_template:
                    behavior_data_str = json.dumps(behavior_data, indent=2)
                    self.logger.debug(
                        f"Replacing {{behavior_data}} placeholder with {len(behavior_data_str)} chars"
                    )
                    full_prompt = full_prompt.replace(
                        "{behavior_data}", behavior_data_str
                    )

                if "{previous_analysis}" in prompt_template:
                    context_str = (
                        context if context else "No previous analysis available"
                    )
                    full_prompt = full_prompt.replace(
                        "{previous_analysis}", context_str
                    )

                if context and "{previous_analysis}" not in prompt_template:
                    full_prompt = f"{full_prompt}\n\nCONTEXT:\n{context}"

                return full_prompt

            except json.JSONDecodeError as e:
                self.logger.error(f"JSON decode error for behavior data: {e}")
                return (
                    f"{prompt_template}\n\n{context}\n\nANALYSIS DATA:\n{input_data}"
                    if context
                    else f"{prompt_template}\n\nANALYSIS DATA:\n{input_data}"
                )
        else:
            return (
                f"{prompt_template}\n\n{context}\n\nANALYSIS DATA:\n{input_data}"
                if context
                else f"{prompt_template}\n\nANALYSIS DATA:\n{input_data}"
            )

    def _build_final_synthesis_prompt(
        self, prompt_template: str, context: str, input_data: str
    ) -> str:
        """Build special prompt for final synthesis with enhanced context."""
        self.logger.info("Building enhanced final synthesis prompt")

        # Create a more structured context for final synthesis
        enhanced_context = self._enhance_final_synthesis_context(context, input_data)

        # Replace placeholders in template
        full_prompt = prompt_template

        if "{previous_analysis}" in prompt_template:
            self.logger.info(
                f"Replacing {{previous_analysis}} placeholder with {len(enhanced_context)} chars"
            )
            full_prompt = full_prompt.replace("{previous_analysis}", enhanced_context)
        elif "{context}" in prompt_template:
            self.logger.info(
                f"Replacing {{context}} placeholder with {len(enhanced_context)} chars"
            )
            full_prompt = full_prompt.replace("{context}", enhanced_context)
        else:
            # Append context if no placeholder
            self.logger.info(
                f"Appending context to prompt ({len(enhanced_context)} chars)"
            )
            full_prompt = f"{full_prompt}\n\nCONTEXT:\n{enhanced_context}"

        return full_prompt

    def _enhance_final_synthesis_context(self, context: str, input_data: str) -> str:
        """Enhance context for final synthesis with better structure."""
        try:
            # Try to parse the context if it's JSON
            if context.strip().startswith("{"):
                context_data = json.loads(context)
                self.logger.info(
                    f"Parsed context as JSON with keys: {list(context_data.keys())}"
                )

                # Enhance the context with instructions
                enhanced = {
                    "INSTRUCTIONS": {
                        "purpose": "FINAL MALWARE ANALYSIS SYNTHESIS",
                        "task": "Create a comprehensive synthesis integrating ALL previous analyses",
                        "requirements": [
                            "Return a COMPLETE JSON structure with all analysis sections",
                            "Include: analysis_stage, cross_stage_correlation_analysis, integrated_threat_assessment, mitre_attack_integration, investigation_priority_matrix, incident_response_guidance",
                            "Provide detailed threat assessment with confidence levels",
                            "Include specific evidence and indicators",
                            "Recommend mitigation strategies",
                            "Provide executive summary and technical details",
                        ],
                    },
                    "ALL_PREVIOUS_ANALYSES": context_data.get(
                        "COMPLETE_PREVIOUS_ANALYSES", {}
                    ),
                    "ANALYSIS_METADATA": {
                        "total_analyses": len(
                            context_data.get("COMPLETE_PREVIOUS_ANALYSES", {})
                        ),
                        "timestamp": datetime.now().isoformat(),
                        "analysis_id": self.analysis_id,
                    },
                }

                return json.dumps(enhanced, indent=2, default=str)
            else:
                # If context is not JSON, return as-is with enhancement
                enhanced = f"""FINAL SYNTHESIS CONTEXT - INTEGRATE ALL FINDINGS:

{context}

ADDITIONAL DATA:
{input_data}

CRITICAL INSTRUCTION: You are performing the FINAL synthesis of a complete malware analysis. 
You MUST return a COMPLETE JSON structure with these sections:
1. analysis_stage: "stage_6_final_threat_synthesis"
2. cross_stage_correlation_analysis: Detailed integration of findings from all stages
3. integrated_threat_assessment: Overall threat level, confidence, categorization
4. mitre_attack_integration: MITRE ATT&CK tactics and techniques
5. investigation_priority_matrix: Critical findings and response priorities
6. incident_response_guidance: Immediate actions and containment strategies

Return the FULL JSON structure, not just individual findings.
"""
                return enhanced

        except json.JSONDecodeError:
            # Context is not JSON, enhance it
            enhanced = f"""FINAL SYNTHESIS CONTEXT:

{context}

ADDITIONAL DATA:
{input_data}

CRITICAL INSTRUCTION: You are performing the FINAL synthesis of a complete malware analysis. 
You MUST return a COMPLETE JSON structure with all analysis sections, not just individual findings.
"""
            return enhanced

    def _check_response_completeness(self, response: str) -> bool:
        """
        Check if a JSON response is complete.
        Returns True if response appears to be complete JSON.
        """
        if not response:
            return False

        response = response.strip()

        # Check if starts and ends with braces
        if not response.startswith("{"):
            return False

        # Count braces to check balance
        open_braces = response.count("{")
        close_braces = response.count("}")

        if open_braces != close_braces:
            return False

        # Check for incomplete arrays
        open_brackets = response.count("[")
        close_brackets = response.count("]")
        if open_brackets != close_brackets:
            return False

        # Try to parse as JSON
        try:
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                json.loads(json_str)
                return True
        except json.JSONDecodeError:
            return False

        return True

    def _fix_incomplete_json(self, response: str) -> str:
        """
        Attempt to fix incomplete JSON by adding missing closing braces.
        """
        if not response:
            return response

        response = response.strip()

        # Remove markdown code blocks if present
        response = re.sub(r"^```(?:json)?\s*", "", response)
        response = re.sub(r"\s*```$", "", response)

        # Count braces and add missing ones
        open_braces = response.count("{")
        close_braces = response.count("}")

        fixed_response = response

        # Add missing closing braces
        if open_braces > close_braces:
            missing = open_braces - close_braces
            fixed_response += "}" * missing

        # Count brackets and add missing ones
        open_brackets = fixed_response.count("[")
        close_brackets = fixed_response.count("]")

        if open_brackets > close_brackets:
            missing = open_brackets - close_brackets
            fixed_response += "]" * missing

        # Check for trailing comma before closing brace
        lines = fixed_response.split("\n")
        if len(lines) > 1:
            last_line = lines[-2].strip()
            if last_line.endswith(","):
                lines[-2] = last_line[:-1]
                fixed_response = "\n".join(lines)

        return fixed_response

    async def _call_with_fallback(
        self,
        prompt: str,
        preferred_model: Optional[str],
        analysis_id: str,
        section_name: str,
        task_id: str = None,
    ) -> Dict[str, Any]:
        """Call AI model with fallback logic."""
        # Get model priority with section-specific logic
        models = self._get_model_priority(preferred_model, section_name)

        self.logger.info(f"Model priority for {section_name}: {models}")

        # Estimate tokens for debugging
        token_estimate = self._estimate_tokens(prompt)
        self.logger.info(f"Prompt size: {len(prompt)} chars (~{token_estimate} tokens)")

        # ✅ SPECIAL HANDLING FOR FINAL SYNTHESIS - Use larger context model
        if section_name == "final_synthesis":
            self.logger.info(
                "Final synthesis detected - ensuring adequate context window"
            )
            # Prefer models with larger context windows
            if "gemini-2.5-pro" not in models:
                models.insert(0, "gemini-2.5-pro")
            if "gemini-2.5-flash" not in models:
                models.insert(1, "gemini-2.5-flash")

        last_error = None
        for model_name in models:
            try:
                self.logger.info(f"Trying model: {model_name}")

                # Validate prompt size for this model
                if not self._validate_prompt_size(prompt, section_name, model_name):
                    self.logger.warning(
                        f"Prompt too large for {model_name}, skipping..."
                    )
                    continue

                actual_task_id = task_id or section_name

                result = await self.model_service.process_request(
                    prompt=prompt, model_name=model_name, task_id=actual_task_id
                )

                if result.get("response") and len(result["response"].strip()) > 50:
                    self.logger.info(f"{model_name} succeeded")
                    return result
                else:
                    raise Exception("Invalid or empty response")

            except Exception as e:
                last_error = e
                error_msg = str(e).lower()

                self.logger.error(f"{model_name} failed: {error_msg[:100]}")

                if any(keyword in error_msg for keyword in ["rate", "quota", "429"]):
                    await asyncio.sleep(3)
                elif any(
                    keyword in error_msg
                    for keyword in ["token", "length", "too long", "limit"]
                ):
                    self.logger.warning(
                        f"Token limit hit for {model_name}, trying next model..."
                    )
                    continue

        raise Exception(f"All models failed. Last error: {last_error}")

    def _get_model_priority(
        self, preferred_model: Optional[str], section_name: str = None
    ) -> List[str]:
        """Get model priority list, with special handling for behavior analysis."""

        # SPECIAL CASE: Force Gemini Pro for behavior analysis
        if section_name == "behavior_analysis":
            self.logger.info("Using HIGHER-CONTEXT Gemini model for behavior analysis")
            return ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash"]

        models = []
        if preferred_model:
            models.append(preferred_model)

        if hasattr(self.model_service, "fallback_priority"):
            models.extend(
                [m for m in self.model_service.fallback_priority if m not in models]
            )
        else:
            models.extend(
                ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.0-flash-lite"]
            )

        return models

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count for a text string."""
        return len(text) // 4

    def _validate_prompt_size(
        self, prompt: str, section_name: str, model_name: str
    ) -> bool:
        """Check if prompt is within reasonable limits."""
        token_estimate = self._estimate_tokens(prompt)

        model_limits = {
            "gemini-2.5-pro": 2000000,
            "gemini-2.5-flash": 1000000,
            "gemini-2.0-flash": 1000000,
            "gemini-2.0-flash-lite": 1000000,
        }

        limit = model_limits.get(model_name, 8000)

        if token_estimate > limit:
            self.logger.warning(f"Prompt for {section_name} exceeds {model_name} limit")
            self.logger.warning(
                f"Estimated: {token_estimate} tokens, Limit: {limit} tokens"
            )
            self.logger.warning(f"Prompt size: {len(prompt)} characters")
            return False

        safe_threshold = limit * 0.8
        if token_estimate > safe_threshold:
            self.logger.warning(
                f"Prompt for {section_name} is approaching {model_name} limit"
            )
            self.logger.warning(
                f"Estimated: {token_estimate} tokens, Safe limit: {safe_threshold:.0f} tokens"
            )

        return True

    async def _load_prompt(self, filename: str) -> str:
        """Load prompt template from file."""
        path = self.templates_dir / filename
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                self.logger.debug(
                    f"Loaded prompt from {filename} ({len(content)} chars)"
                )
                return content
        except Exception as e:
            self.logger.error(f"Failed to load prompt {filename}: {str(e)}")
            raise Exception(f"Failed to load prompt {filename}: {str(e)}") from e

    def _prepare_input_data(
        self, parsed_results: Dict, section_names: List[str]
    ) -> str:
        """Prepare input data for analysis."""
        if section_names == ["all"]:
            data_to_prepare = parsed_results["sections"].copy()
            if "behavior" in data_to_prepare:
                data_to_prepare["behavior"] = self._clean_behavior_for_ai(
                    data_to_prepare["behavior"]
                )
            return json.dumps(data_to_prepare, indent=2)
        elif section_names == ["all_ai_analyses"]:
            return ""
        else:
            if len(section_names) == 1 and section_names[0] == "behavior":
                if "behavior" in parsed_results["sections"]:
                    behavior_data = parsed_results["sections"]["behavior"]
                    cleaned_behavior = self._clean_behavior_for_ai(behavior_data)

                    self.logger.debug(
                        f"Preparing input data for behavior - cleaned_behavior type: {type(cleaned_behavior)}"
                    )

                    if "data" not in cleaned_behavior:
                        self.logger.warning("'data' key missing in cleaned_behavior!")
                        cleaned_behavior = {"data": cleaned_behavior}

                    return json.dumps(cleaned_behavior, indent=2)
                else:
                    return json.dumps({}, indent=2)
            else:
                data = {}
                for name in section_names:
                    if name in parsed_results["sections"]:
                        section_data = parsed_results["sections"][name]
                        if name == "behavior":
                            section_data = self._clean_behavior_for_ai(section_data)
                        data[name] = section_data

                return json.dumps(data, indent=2)

    def _clean_behavior_for_ai(self, behavior_data: Dict) -> Dict:
        """
        Create a cleaned version of behavior data for AI analysis.
        Removes verbose sections (calls and enhanced) to reduce token count.
        """
        if not behavior_data or "data" not in behavior_data:
            self.logger.warning(
                f"clean_behavior - Invalid input: {type(behavior_data)}"
            )
            return behavior_data

        self.logger.info("Cleaning behavior data...")

        import copy

        cleaned = copy.deepcopy(behavior_data)

        # Calculate original size
        original_json = json.dumps(behavior_data)
        original_size = len(original_json)

        # Clean processes (remove calls section)
        if "processes" in cleaned["data"]:
            process_count = len(cleaned["data"]["processes"])
            self.logger.info(f"Found {process_count} processes")
            total_calls_removed = 0

            for process in cleaned["data"]["processes"]:
                if "calls" in process:
                    call_count = len(process["calls"])
                    if call_count > 40:
                        important_calls = process["calls"][:20] + process["calls"][-20:]
                        process["calls"] = important_calls
                        removed = call_count - 40
                        total_calls_removed += removed
                        process["calls_summary"] = {
                            "total_original_calls": call_count,
                            "calls_preserved": 40,
                            "note": f"{removed} routine calls removed for brevity",
                        }
                    else:
                        process["calls_summary"] = {
                            "total_calls": call_count,
                            "note": f"All {call_count} calls preserved",
                        }

            self.logger.info(
                f"Processed calls, total calls removed: {total_calls_removed}"
            )

        # Summarize enhanced section instead of removing
        if "enhanced" in cleaned["data"]:
            enhanced_count = len(cleaned["data"]["enhanced"])
            if enhanced_count > 100:
                cleaned["data"]["enhanced"] = cleaned["data"]["enhanced"][:100]
                cleaned["data"]["enhanced_summary"] = {
                    "total_original_events": enhanced_count,
                    "events_preserved": 100,
                    "note": f"Top 100 most relevant enhanced events shown",
                }
                self.logger.info(
                    f"Enhanced events reduced from {enhanced_count} to 100"
                )

        # Calculate cleaned size
        cleaned_json = json.dumps(cleaned)
        cleaned_size = len(cleaned_json)
        reduction = ((original_size - cleaned_size) / original_size) * 100

        self.logger.info(
            f"Size reduction: {reduction:.1f}% ({original_size:,} → {cleaned_size:,} chars)"
        )

        return cleaned

    def _build_context(
        self, previous_analyses: Dict, section_config: Dict, section_name: str
    ) -> str:
        """
        Build context from previous analyses.

        ✅ MODIFIED: For final_synthesis, send COMPLETE previous analyses without filtering.
        """
        if not section_config.get("requires_previous") or not previous_analyses:
            return ""

        if section_name == "final_synthesis":
            self.logger.info(
                "Building context for final_synthesis - sending COMPLETE previous analyses"
            )

            # ✅ Send everything - no filtering
            complete_context = {
                "COMPLETE_PREVIOUS_ANALYSES": previous_analyses,
                "ANALYSIS_SUMMARY": self._create_analysis_summary(previous_analyses),
                "NOTE": "This contains all previous analysis results without filtering. "
                "You MUST return a COMPLETE JSON structure, not just individual findings.",
            }

            context_str = json.dumps(complete_context, indent=2, default=str)
            self.logger.debug(f"Final synthesis context size: {len(context_str)} chars")

            return context_str

        # For other sections, use filtered approach
        context_data = {
            name: analysis.get("analysis")
            for name, analysis in previous_analyses.items()
            if "analysis" in analysis
        }

        if context_data:
            context_str = "ANALYSIS CONTEXT:\n" + json.dumps(
                context_data, indent=2, default=str
            )
            self.logger.debug(
                f"Built context for {section_name}: {len(context_str)} chars"
            )
            return context_str

        return ""

    def _create_analysis_summary(self, previous_analyses: Dict) -> Dict:
        """Create a summary of all previous analyses for final synthesis."""
        summary = {
            "total_sections": len(previous_analyses),
            "sections_available": list(previous_analyses.keys()),
            "section_status": {},
        }

        for section, analysis in previous_analyses.items():
            status = {
                "type": analysis.get("type", "unknown"),
                "status": analysis.get("status", "unknown"),
                "has_analysis": "analysis" in analysis,
                "model_used": analysis.get("ai_model", "unknown"),
            }

            if "analysis" in analysis and isinstance(analysis["analysis"], dict):
                status["analysis_keys"] = list(analysis["analysis"].keys())

            summary["section_status"][section] = status

        return summary

    def _build_chunk_context(
        self, previous_chunk: Optional[Dict[str, Any]], base_context: str
    ) -> str:
        """Build context for continuation chunks."""
        if not previous_chunk:
            return base_context

        context_data = {
            "previous_chunk_analysis": previous_chunk.get("analysis", {}),
            "base_context": base_context,
        }

        return "CONTINUATION CONTEXT:\n" + json.dumps(
            context_data, indent=2, default=str
        )

    def _build_prompt(
        self,
        template: str,
        context: str,
        chunk_data: Dict,
        chunk_info: Dict,
        section_name: str,
    ) -> str:
        """Build complete prompt for AI analysis."""
        # For behavior analysis in chunks
        if section_name == "behavior_analysis":
            if "{behavior_data}" in template:
                template = template.replace(
                    "{behavior_data}", json.dumps(chunk_data, indent=2)
                )
            if "{previous_analysis}" in template:
                template = template.replace("{previous_analysis}", context)

            if context and "{previous_analysis}" not in template:
                return f"{template}\n\n{context}"
            else:
                return template

        # For other sections
        prompt = template.replace("{chunk_info}", json.dumps(chunk_info, indent=2))
        prompt = prompt.replace("{section_data}", json.dumps(chunk_data, indent=2))

        return f"{prompt}\n\n{context}" if context else prompt

    def _get_chunks(self, section_name: str, section_data: Dict) -> List:
        """Get chunks for a section."""
        if section_name == "behavior_analysis":
            return self.chunking_service.chunk_behavior_data(section_data)
        elif section_name == "strings_analysis":
            self.logger.warning("Skipping strings analysis chunking")
            from dataclasses import dataclass
            from typing import Any

            @dataclass
            class SimpleChunkInfo:
                current_chunk: int = 1
                total_chunks: int = 1
                items_in_chunk: int = 0
                estimated_tokens: int = 0
                additional_metrics: Optional[dict] = None

            @dataclass
            class SimpleChunkedData:
                data: Any
                chunk_info: SimpleChunkInfo

            return [
                SimpleChunkedData(data={"skipped": True}, chunk_info=SimpleChunkInfo())
            ]
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
        """Check if section has data available."""
        return section_config["input_sections"][0] in parsed_results["sections"]

    def _combine_chunks(self, chunk_results: List[Dict]) -> Dict[str, Any]:
        """Combine analysis results from multiple chunks into a summary."""
        successful = [c for c in chunk_results if "analysis" in c]

        if not successful:
            self.logger.warning(f"All chunks failed: {len(chunk_results)} total")
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

        self.logger.info(f"Combined {len(successful)} chunks successfully")
        return combined
