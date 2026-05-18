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
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)

        logger_name = f"section_analyzer_{self.analysis_id}"
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.DEBUG)

        logger.handlers.clear()

        log_file = logs_dir / f"analysis_{self.analysis_id}.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)

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
        threat_intel_context: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Analyze a specific section using AI."""
        section_name = section_config.get("section")
        self.logger.info(f"Starting analysis for section: {section_name}")

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

            context = self._build_context(
                previous_analyses,
                section_config,
                section_name,
                threat_intel_context,
            )

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

        self.logger.info(f"Previous analyses count: {len(previous_analyses)}")
        for section, analysis in previous_analyses.items():
            self.logger.info(f"  - {section}:")
            if isinstance(analysis, dict):
                self.logger.info(f"    Type: {analysis.get('type', 'unknown')}")
                self.logger.info(f"    Status: {analysis.get('status', 'unknown')}")
                self.logger.info(
                    f"    Timestamp: {analysis.get('timestamp', 'unknown')}"
                )

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

        self.logger.info(f"Context size: {len(context)} characters")
        if len(context) > 0:
            self.logger.info(f"Context preview (first 500 chars):")
            self.logger.info(context[:500] + "..." if len(context) > 500 else context)

        self.logger.info(f"Input data size: {len(input_data)} characters")

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

        if section_name == "behavior_analysis":
            section_data = self._clean_behavior_for_ai(section_data)
        elif section_name == "network_analysis":
            section_data = self._clean_network_for_ai(section_data)

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

        tasks = [
            process_single_chunk(idx, chunk)
            for idx, chunk in enumerate(chunked_data_list)
        ]
        chunk_results = await asyncio.gather(*tasks)

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
        """Process chunks sequentially."""
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

        if section_name == "strings_analysis":
            self.logger.warning("Skipping strings analysis (standard mode)")
            return {
                "section": "strings_analysis",
                "type": "skipped",
                "status": "skipped",
                "note": "Strings analysis disabled as per configuration",
                "timestamp": datetime.now().isoformat(),
            }

        if section_name == "final_synthesis":
            self.logger.info("=== FINAL SYNTHESIS ANALYSIS START ===")
            self.logger.info(f"Context provided: {len(context)} characters")
            self.logger.info(f"Input data: {len(input_data)} characters")

            full_prompt = self._build_final_synthesis_prompt(
                prompt_template, context, input_data
            )

            prompt_file = Path(f"logs/final_synthesis_prompt_{self.analysis_id}.txt")
            prompt_file.write_text(full_prompt, encoding="utf-8")
            self.logger.info(f"Saved final synthesis prompt to: {prompt_file}")

            self.logger.info(
                f"Final synthesis prompt size: {len(full_prompt)} characters"
            )

        else:
            full_prompt = self._build_standard_prompt(
                section_name, prompt_template, input_data, context
            )

        try:
            if section_name == "final_synthesis":
                self.logger.info("Sending final synthesis to AI...")

            result = await self._call_with_fallback(
                full_prompt, model_name, analysis_id, section_name, section_name
            )

            if section_name in ["behavior_analysis", "network_analysis", "final_synthesis"]:
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

            if section_name == "final_synthesis":
                analysis = self._extract_final_synthesis(result.get("response", ""))
            else:
                analysis = self.json_extractor.extract(result.get("response", ""))

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

                    for key in [
                        "analysis_stage",
                        "cross_stage_correlation_analysis",
                        "integrated_threat_assessment",
                        "mitre_attack_integration",
                    ]:
                        if key in analysis:
                            self.logger.info(f"  - {key}: Present")

                    if "cross_stage_correlation_analysis" in analysis:
                        correlation = analysis["cross_stage_correlation_analysis"]
                        if "evidence_convergence" in correlation:
                            convergence = correlation["evidence_convergence"]
                            if "strongly_correlated_findings" in convergence:
                                findings = convergence["strongly_correlated_findings"]
                                self.logger.info(f"  - Findings count: {len(findings)}")

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

    def _clean_network_for_ai(self, network_data: Dict) -> Dict:
        """
        Clean network data for AI analysis.
        Ensures network data is properly structured with ai_summary or full data.
        """
        if not network_data:
            self.logger.warning("clean_network - Invalid input: empty")
            return {"has_network_activity": False, "domains": [], "ips": []}

        self.logger.info("Cleaning network data for AI...")

        import copy

        cleaned = copy.deepcopy(network_data)

        # If network data has ai_summary, use it directly (already compact)
        if isinstance(cleaned, dict) and "ai_summary" in cleaned:
            self.logger.info("Network data already has ai_summary, using it directly")
            return cleaned["ai_summary"]

        # If network data has full structure, extract ai_summary
        if isinstance(cleaned, dict) and "full" in cleaned:
            if "ai_summary" in cleaned:
                self.logger.info("Using ai_summary from full/ai_summary structure")
                return cleaned["ai_summary"]
            elif "full" in cleaned and isinstance(cleaned["full"], dict):
                # Try to extract from full model
                full_data = cleaned["full"]
                ai_summary = {
                    "has_network_activity": bool(
                        full_data.get("domains") or full_data.get("hosts") or full_data.get("dns")
                    ),
                    "domains": [d.get("domain") for d in full_data.get("domains", [])[:30]],
                    "ips": [h.get("ip") for h in full_data.get("hosts", [])[:30] if h.get("ip")],
                    "dns_queries": [
                        {"request": d.get("request"), "type": d.get("type")}
                        for d in full_data.get("dns", [])[:20]
                    ],
                    "http_requests": [
                        {"method": h.get("method"), "host": h.get("host"), "path": h.get("path", "")[:100]}
                        for h in full_data.get("http", [])[:15]
                    ],
                    "total_tcp_connections": len(full_data.get("tcp", [])),
                    "total_udp_connections": len(full_data.get("udp", [])),
                    "total_dns_queries": len(full_data.get("dns", [])),
                    "total_http_requests": len(full_data.get("http", [])),
                    "has_suspicious_domains": any(
                        any(k in d.get("domain", "").lower() for k in ["tk", "ml", "xyz", "ddns", "no-ip"])
                        for d in full_data.get("domains", [])
                    ),
                    "has_dns_traffic": len(full_data.get("dns", [])) > 0,
                    "has_https_traffic": any(h.get("port") == 443 or "https" in str(h.get("host", "")).lower() 
                                            for h in full_data.get("http", [])),
                }
                ai_summary["quick_summary"] = self._generate_network_quick_summary(ai_summary)
                self.logger.info("Generated ai_summary from full network data")
                return ai_summary

        # If network data is already the AI summary format
        if isinstance(cleaned, dict) and "domains" in cleaned and "ips" in cleaned:
            self.logger.info("Network data already in AI summary format")
            return cleaned

        original_size = len(json.dumps(network_data)) if network_data else 0
        cleaned_size = len(json.dumps(cleaned)) if cleaned else 0
        reduction = (
            ((original_size - cleaned_size) / original_size) * 100
            if original_size > 0
            else 0
        )

        self.logger.info(
            "Network data size reduction: %.1f%% (%d → %d chars)",
            reduction,
            original_size,
            cleaned_size,
        )

        return cleaned

    def _generate_network_quick_summary(self, ai_summary: Dict) -> str:
        """Generate quick summary string for network data."""
        parts = []
        
        domains = ai_summary.get("domains", [])
        if domains:
            parts.append(f"Domains: {len(domains)}")
            if domains:
                parts.append(f"Top domain: {domains[0][:50]}")
        
        ips = ai_summary.get("ips", [])
        if ips:
            parts.append(f"IPs: {len(ips)}")
        
        http = ai_summary.get("http_requests", [])
        if http:
            parts.append(f"HTTP: {len(http)}")
        
        dns = ai_summary.get("dns_queries", [])
        if dns:
            parts.append(f"DNS: {len(dns)}")
        
        dead_hosts = ai_summary.get("dead_hosts", [])
        if dead_hosts:
            parts.append(f"Dead hosts: {len(dead_hosts)}")
        
        if ai_summary.get("has_suspicious_domains"):
            parts.append("Suspicious domains detected")
        
        return " | ".join(parts) if parts else "No network activity"

    def _extract_final_synthesis(self, response: str) -> Dict[str, Any]:
        """Special extraction for final synthesis responses."""
        try:
            extracted = self.json_extractor.extract(response)

            if isinstance(extracted, dict):
                self.logger.info(
                    f"Extracted final synthesis structure: {list(extracted.keys())}"
                )

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
                    self.logger.warning(
                        "Only minimal extraction found, attempting to extract full JSON"
                    )
                    return self._extract_full_final_synthesis(response)
                else:
                    return extracted

            return self._extract_full_final_synthesis(response)

        except Exception as e:
            self.logger.error(f"Error extracting final synthesis: {e}")
            return self._extract_full_final_synthesis(response)

    def _extract_full_final_synthesis(self, response: str) -> Dict[str, Any]:
        """Extract the complete final synthesis JSON from the response."""
        try:
            cleaned = response.strip()

            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)

            json_pattern = r"\{.*\}"
            matches = re.findall(json_pattern, cleaned, re.DOTALL)

            if matches:
                for match in matches:
                    try:
                        parsed = json.loads(match)
                        self.logger.info(f"Successfully parsed JSON from response")

                        if isinstance(parsed, dict):
                            minimal_keys = {
                                "finding_description",
                                "supporting_stages",
                                "evidence_types",
                                "convergence_strength",
                            }
                            if minimal_keys.issubset(set(parsed.keys())):
                                self.logger.warning(
                                    "Parsed JSON appears to be a minimal finding, not full synthesis"
                                )
                                continue

                            if (
                                "analysis_stage" in parsed
                                or "cross_stage_correlation_analysis" in parsed
                            ):
                                self.logger.info("Found full final synthesis structure")
                                return parsed

                    except json.JSONDecodeError:
                        continue

            try:
                parsed = json.loads(cleaned)
                self.logger.info("Parsed entire response as JSON")
                return parsed
            except json.JSONDecodeError:
                pass

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
        elif section_name == "network_analysis":
            try:
                network_data = json.loads(input_data) if input_data else {}
                self.logger.debug(
                    f"Network analysis - Raw network_data type: {type(network_data)}"
                )

                full_prompt = prompt_template

                if "{network_data}" in prompt_template:
                    network_data_str = json.dumps(network_data, indent=2)
                    self.logger.debug(
                        f"Replacing {{network_data}} placeholder with {len(network_data_str)} chars"
                    )
                    full_prompt = full_prompt.replace("{network_data}", network_data_str)

                if "{previous_analysis}" in prompt_template:
                    context_str = context if context else "No previous analysis available"
                    full_prompt = full_prompt.replace("{previous_analysis}", context_str)

                if context and "{previous_analysis}" not in prompt_template:
                    full_prompt = f"{full_prompt}\n\nCONTEXT:\n{context}"

                return full_prompt

            except json.JSONDecodeError as e:
                self.logger.error(f"JSON decode error for network data: {e}")
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

        enhanced_context = self._enhance_final_synthesis_context(context, input_data)

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
            self.logger.info(
                f"Appending context to prompt ({len(enhanced_context)} chars)"
            )
            full_prompt = f"{full_prompt}\n\nCONTEXT:\n{enhanced_context}"

        return full_prompt

    def _enhance_final_synthesis_context(self, context: str, input_data: str) -> str:
        """Enhance context for final synthesis with better structure."""
        try:
            if context.strip().startswith("{"):
                context_data = json.loads(context)
                self.logger.info(
                    f"Parsed context as JSON with keys: {list(context_data.keys())}"
                )

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

                if "THREAT_INTELLIGENCE" in context_data:
                    enhanced["THREAT_INTELLIGENCE"] = context_data["THREAT_INTELLIGENCE"]
                    enhanced["TI_GUIDANCE"] = context_data.get("TI_GUIDANCE", {})
                    self.logger.info(
                        "✅ Threat Intelligence included in final synthesis context"
                    )

                return json.dumps(enhanced, indent=2, default=str)
            else:
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
            enhanced = f"""FINAL SYNTHESIS CONTEXT:

{context}

ADDITIONAL DATA:
{input_data}

CRITICAL INSTRUCTION: You are performing the FINAL synthesis of a complete malware analysis. 
You MUST return a COMPLETE JSON structure with all analysis sections, not just individual findings.
"""
            return enhanced

    def _check_response_completeness(self, response: str) -> bool:
        """Check if a JSON response is complete."""
        if not response:
            return False

        response = response.strip()

        if not response.startswith("{"):
            return False

        open_braces = response.count("{")
        close_braces = response.count("}")

        if open_braces != close_braces:
            return False

        open_brackets = response.count("[")
        close_brackets = response.count("]")
        if open_brackets != close_brackets:
            return False

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
        """Attempt to fix incomplete JSON by adding missing closing braces."""
        if not response:
            return response

        response = response.strip()

        response = re.sub(r"^```(?:json)?\s*", "", response)
        response = re.sub(r"\s*```$", "", response)

        open_braces = response.count("{")
        close_braces = response.count("}")

        fixed_response = response

        if open_braces > close_braces:
            missing = open_braces - close_braces
            fixed_response += "}" * missing

        open_brackets = fixed_response.count("[")
        close_brackets = fixed_response.count("]")

        if open_brackets > close_brackets:
            missing = open_brackets - close_brackets
            fixed_response += "]" * missing

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
        models = self._get_model_priority(preferred_model, section_name)

        self.logger.info(f"Model priority for {section_name}: {models}")

        token_estimate = self._estimate_tokens(prompt)
        self.logger.info(f"Prompt size: {len(prompt)} chars (~{token_estimate} tokens)")

        if section_name == "final_synthesis":
            self.logger.info(
                "Final synthesis detected - ensuring adequate context window"
            )
            if "gemini-2.5-pro" not in models:
                models.insert(0, "gemini-2.5-pro")
            if "gemini-2.5-flash" not in models:
                models.insert(1, "gemini-2.5-flash")

        last_error = None
        for model_name in models:
            try:
                self.logger.info(f"Trying model: {model_name}")

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
        """Get model priority list, with special handling for behavior and network analysis."""

        if section_name in ["behavior_analysis", "network_analysis"]:
            self.logger.info(f"Using HIGHER-CONTEXT Gemini model for {section_name}")
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
        """
        Prepare input data for AI analysis.
        Sends FULL parsed data for info, statistics, cape, target, memory, signatures, network since parsers already removed bloat.
        For other sections, uses ai_summary or summary if available.
        """
        if section_names == ["all_ai_analyses"]:
            return self._prepare_all_ai_analyses(parsed_results)
        if section_names == ["all"]:
            return self._prepare_all_sections_compact(parsed_results)
        if len(section_names) == 1:
            return self._prepare_single_section(parsed_results, section_names[0])
        return self._prepare_multiple_sections(parsed_results, section_names)

    def _prepare_all_ai_analyses(self, parsed_results: Dict) -> str:
        """
        Prepare data for final synthesis - sends FULL data for main sections,
        uses ai_summary/summary for others.
        """
        combined: Dict[str, Any] = {}

        ai_sections = [
            "info",
            "statistics",
            "cape",
            "target",
            "memory",
            "signatures",
            "network",
            "behavior",
        ]

        # Sections that should send FULL data (already compacted by parsers)
        full_data_sections = {"info", "statistics", "cape", "target", "memory", "signatures", "network"}

        sections = parsed_results.get("sections", {})
        for section_name in ai_sections:
            if section_name in sections:
                section_data = sections[section_name]
                
                # Send full data for compacted sections
                if section_name in full_data_sections:
                    combined[section_name] = section_data
                # For other sections, prefer ai_summary or summary
                elif isinstance(section_data, dict) and "ai_summary" in section_data:
                    combined[section_name] = section_data["ai_summary"]
                elif isinstance(section_data, dict) and "summary" in section_data:
                    combined[section_name] = section_data["summary"]
                else:
                    self.logger.warning(
                        "Section %s has no ai_summary or summary, using full data",
                        section_name,
                    )
                    combined[section_name] = section_data

        self.logger.info("Prepared %d sections for final synthesis", len(combined))
        self.logger.debug("Combined data size: %d chars", len(json.dumps(combined)))

        return json.dumps(combined, indent=2, default=str)

    def _prepare_all_sections_compact(self, parsed_results: Dict) -> str:
        """
        Prepare compact version of all sections for initial combined analysis.
        Sends FULL data for info, statistics, cape, target, memory, signatures, network.
        """
        compact_data: Dict[str, Any] = {}
        sections = parsed_results.get("sections", {})

        # Sections that should send FULL data (already compacted by parsers)
        full_data_sections = {"info", "statistics", "cape", "target", "memory", "signatures", "network"}

        for section_name, section_data in sections.items():
            if section_name in full_data_sections:
                compact_data[section_name] = section_data
            else:
                data_size = len(json.dumps(section_data)) if section_data else 0
                if data_size > 10000:
                    self.logger.warning(
                        "Section %s is large (%d chars), consider compacting",
                        section_name,
                        data_size,
                    )
                compact_data[section_name] = section_data

        result_json = json.dumps(compact_data, indent=2, default=str)
        self.logger.info(
            "Prepared compact data for all sections: %d chars", len(result_json)
        )

        return result_json

    def _prepare_single_section(self, parsed_results: Dict, section_name: str) -> str:
        """
        Prepare a single section for analysis.
        Sends FULL data for info, statistics, cape, target, memory, signatures, network.
        For others, uses ai_summary if available, otherwise full section.
        """
        sections = parsed_results.get("sections", {})

        if section_name not in sections:
            self.logger.warning("Section %s not found in parsed results", section_name)
            return json.dumps({})

        section_data = sections[section_name]

        # Sections that should send FULL data (already compacted by parsers)
        full_data_sections = {"info", "statistics", "cape", "target", "memory", "signatures", "network"}

        if section_name in full_data_sections:
            data_to_send = section_data
            result_json = json.dumps(data_to_send, indent=2, default=str)
            self.logger.info("Prepared %s: %d chars", section_name, len(result_json))
            return result_json

        if isinstance(section_data, dict):
            if "ai_summary" in section_data:
                data_to_send = section_data["ai_summary"]
                self.logger.debug("Using ai_summary for %s", section_name)
            elif "summary" in section_data:
                data_to_send = section_data["summary"]
                self.logger.debug("Using summary for %s", section_name)
            else:
                data_to_send = section_data
                self.logger.debug("Using full data for %s", section_name)
        else:
            data_to_send = section_data

        result_json = json.dumps(data_to_send, indent=2, default=str)
        self.logger.info("Prepared %s: %d chars", section_name, len(result_json))

        return result_json

    def _prepare_multiple_sections(
        self, parsed_results: Dict, section_names: List[str]
    ) -> str:
        """
        Prepare multiple specific sections.
        Sends FULL data for info, statistics, cape, target, memory, signatures, network.
        For others, uses compact versions where available.
        """
        combined: Dict[str, Any] = {}
        sections = parsed_results.get("sections", {})

        # Sections that should send FULL data (already compacted by parsers)
        full_data_sections = {"info", "statistics", "cape", "target", "memory", "signatures", "network"}

        for section_name in section_names:
            if section_name not in sections:
                self.logger.warning("Section %s not found", section_name)
                continue

            section_data = sections[section_name]

            if section_name in full_data_sections:
                combined[section_name] = section_data
            elif isinstance(section_data, dict):
                if "ai_summary" in section_data:
                    combined[section_name] = section_data["ai_summary"]
                elif "summary" in section_data:
                    combined[section_name] = section_data["summary"]
                else:
                    combined[section_name] = section_data
            else:
                combined[section_name] = section_data

        result_json = json.dumps(combined, indent=2, default=str)
        self.logger.info(
            "Prepared %d sections: %d chars", len(combined), len(result_json)
        )

        return result_json

    def _compact_summary_only(self, section_data: Dict) -> Dict:
        """Keep only the summary object for already-compacted metadata sections."""
        if not isinstance(section_data, dict):
            return section_data

        summary = section_data.get("summary")
        if summary is None:
            return section_data

        return {"summary": summary}

    def _compact_cape_section(self, section_data: Dict) -> Dict:
        """Keep the compact CAPE payload/config preview and its summary only."""
        if not isinstance(section_data, dict):
            return section_data

        compact = {
            "payloads": section_data.get("payloads", []),
            "configs": section_data.get("configs", []),
            "summary": section_data.get("summary", {}),
        }
        return compact

    def _compact_target_section(self, section_data: Dict) -> Dict:
        """Keep compact target summary and detection highlights only."""
        if not isinstance(section_data, dict):
            return section_data

        compact = {
            "summary": section_data.get("summary", {}),
            "detections": section_data.get("detections", []),
            "detections2pid": section_data.get("detections2pid", []),
        }
        return compact

    def _compact_initial_context_sections(self, sections: Dict[str, Any]) -> Dict[str, Any]:
        """Reduce initial context sections to the smallest prompt-safe form."""
        compacted = {}
        for name, section_data in sections.items():
            if name in {"info", "statistics"}:
                compacted[name] = self._compact_summary_only(section_data)
            elif name == "cape":
                compacted[name] = self._compact_cape_section(section_data)
            elif name == "target":
                compacted[name] = self._compact_target_section(section_data)
            else:
                compacted[name] = section_data
        return compacted

    def _clean_behavior_for_ai(self, behavior_data: Dict) -> Dict:
        """
        Clean behavior data for AI analysis.
        Handles new parser format with full/ai_summary.
        """
        if not behavior_data:
            self.logger.warning("clean_behavior - Invalid input: empty")
            return {"total_processes": 0, "quick_summary": "No behavior data"}

        self.logger.info("Cleaning behavior data for AI...")

        import copy

        cleaned = copy.deepcopy(behavior_data)

        # New parser format: { "full": {...}, "ai_summary": {...} }
        if isinstance(cleaned, dict):
            # If already has ai_summary, use it directly
            if "ai_summary" in cleaned:
                self.logger.info("Behavior data already has ai_summary, using it directly")
                return cleaned["ai_summary"]
            
            # If has full structure but no ai_summary (shouldn't happen), extract from full
            if "full" in cleaned and isinstance(cleaned["full"], dict):
                full_data = cleaned["full"]
                # Build minimal ai_summary from full data
                ai_summary = {
                    "total_processes": len(full_data.get("processes", [])),
                    "total_api_calls": sum(len(p.get("calls", [])) for p in full_data.get("processes", [])),
                    "quick_summary": f"Found {len(full_data.get('processes', []))} processes"
                }
                self.logger.info("Generated ai_summary from full behavior data")
                return ai_summary
            
            # If already in AI summary format
            if "total_processes" in cleaned:
                self.logger.info("Behavior data already in AI summary format")
                return cleaned

        # Fallback for old format (with data.processes)
        if "data" in cleaned and isinstance(cleaned["data"], dict):
            data = cleaned["data"]
            
            if "processes" in data:
                processes = data["processes"]
                for process in processes:
                    if "calls" in process:
                        call_count = len(process["calls"])
                        if call_count > 40:
                            process["calls"] = process["calls"][:20] + process["calls"][-20:]
                            process["calls_summary"] = {
                                "total_original_calls": call_count,
                                "calls_preserved": 40
                            }
            
            if "enhanced" in data and len(data["enhanced"]) > 100:
                data["enhanced"] = data["enhanced"][:100]
                data["enhanced_summary"] = {"events_preserved": 100}
            
            original_json = json.dumps(behavior_data)
            original_size = len(original_json)
            cleaned_json = json.dumps(cleaned)
            cleaned_size = len(cleaned_json)
            reduction = (
                ((original_size - cleaned_size) / original_size) * 100
                if original_size > 0
                else 0
            )

            self.logger.info(
                "Behavior data size reduction: %.1f%% (%d → %d chars)",
                reduction,
                original_size,
                cleaned_size,
            )

        return cleaned

    def _build_context(
        self,
        previous_analyses: Dict,
        section_config: Dict,
        section_name: str,
        threat_intel_context: Optional[Dict] = None,
    ) -> str:
        """Build context from previous analyses."""
        if not section_config.get("requires_previous") or not previous_analyses:
            return ""

        if section_name == "final_synthesis":
            self.logger.info(
                "Building context for final_synthesis - sending COMPLETE previous analyses"
            )

            complete_context = {
                "COMPLETE_PREVIOUS_ANALYSES": previous_analyses,
                "ANALYSIS_SUMMARY": self._create_analysis_summary(previous_analyses),
                "IMPORTANT_NOTE": (
                    "The threat intelligence results below are AUTHORITATIVE. "
                    "If multiple threat intel sources show the file as CLEAN, "
                    "you MUST weigh this heavily in your final assessment. "
                    "Sandbox behavioral scores can have false positives - "
                    "cross-reference with threat intel before making conclusions."
                ),
            }

            if threat_intel_context:
                complete_context["THREAT_INTELLIGENCE"] = threat_intel_context
                complete_context["TI_GUIDANCE"] = {
                    "how_to_use_ti": (
                        "1. If VirusTotal shows 0/X detections and file is signed, "
                        "this strongly suggests LEGITIMATE software\n"
                        "2. If MalwareBazaar, Hybrid Analysis, and OTX all show 'Not Found', "
                        "the file is likely not malware\n"
                        "3. A high sandbox score + clean threat intel = possible false positive\n"
                        "4. Adjust your threat_score accordingly - do NOT give 8.5/10 "
                        "to a signed Google installer with 0/72 VT detections\n"
                        "5. Legitimate software installers (Chrome, Firefox, etc.) will "
                        "exhibit 'suspicious' behaviors (registry changes, network connections) - "
                        "this is NORMAL and not malicious"
                    ),
                    "scoring_rules": {
                        "vt_clean_and_signed": "threat_score MUST be ≤ 2.0/10",
                        "all_ti_clean": "threat_score MUST be ≤ 3.0/10",
                        "mixed_results": "weigh threat intel MORE than sandbox behavior",
                        "ti_confirms_malicious": "can trust sandbox score with higher confidence",
                    },
                }
                self.logger.info(
                    "✅ Threat intelligence context included in final synthesis"
                )
            else:
                self.logger.warning(
                    "⚠️ No threat intelligence context available for final synthesis"
                )

            context_str = json.dumps(complete_context, indent=2, default=str)
            self.logger.debug(f"Final synthesis context size: {len(context_str)} chars")

            return context_str

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
        elif section_name == "network_analysis":
            if "{network_data}" in template:
                template = template.replace(
                    "{network_data}", json.dumps(chunk_data, indent=2)
                )
            if "{previous_analysis}" in template:
                template = template.replace("{previous_analysis}", context)

            if context and "{previous_analysis}" not in template:
                return f"{template}\n\n{context}"
            else:
                return template

        prompt = template.replace("{chunk_info}", json.dumps(chunk_info, indent=2))
        prompt = prompt.replace("{section_data}", json.dumps(chunk_data, indent=2))

        return f"{prompt}\n\n{context}" if context else prompt

    def _get_chunks(self, section_name: str, section_data: Dict) -> List:
        """Get chunks for a section."""
        if section_name == "behavior_analysis":
            return self.chunking_service.chunk_behavior_data(section_data)
        elif section_name == "network_analysis":
            return self.chunking_service.chunk_network_data(section_data)
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
        input_sections = section_config.get("input_sections", [])
        if not input_sections:
            return False

        section_name = input_sections[0]
        sections = parsed_results.get("sections", {})

        if section_name not in sections:
            return False

        section_data = sections[section_name]

        if isinstance(section_data, dict):
            if "ai_summary" in section_data:
                ai_summary = section_data["ai_summary"]
                if isinstance(ai_summary, dict):
                    if ai_summary.get("detected_families") or ai_summary.get(
                        "total_payloads", 0
                    ) > 0:
                        return True
                    if ai_summary.get("domains") and len(ai_summary.get("domains", [])) > 0:
                        return True
                    if (
                        ai_summary.get("quick_summary")
                        and ai_summary["quick_summary"]
                        != "No CAPE data extracted"
                    ):
                        return True
                return bool(ai_summary)

            if "summary" in section_data:
                return bool(section_data["summary"])

            if section_name == "statistics" and section_data.get("processing_summary"):
                return True

            if section_data and len(section_data) > 0:
                return True

        return bool(section_data)

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