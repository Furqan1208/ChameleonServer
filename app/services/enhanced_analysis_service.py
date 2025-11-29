# D:\FYP\ChameleonServer\app\services\enhanced_analysis_service.py
import json
import asyncio
import re
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime


class EnhancedAnalysisService:
    """
    Enhanced analysis service with chunking support for large sections (behavior, strings)
    and robust fallback mechanisms.
    """
    
    def __init__(self, model_service, parser_service, chunking_service):
        self.model_service = model_service
        self.parser_service = parser_service
        self.chunking_service = chunking_service
        self.templates_dir = Path("app/templates/section_prompts")
        
        # Section analysis configuration with chunking support
        self.analysis_plan = [
            {
                "section": "initial_combined_analysis",
                "prompt_file": "initial_combined_analysis_prompt.txt",
                "input_sections": ["info", "statistics", "cape"],
                "requires_previous": False,
                "chunkable": False,
                "priority": 1
            },
            {
                "section": "target_analysis", 
                "prompt_file": "target_analysis_prompt.txt",
                "input_sections": ["target"],
                "requires_previous": True,
                "chunkable": False,
                "priority": 2
            },
            {
                "section": "memory_analysis",
                "prompt_file": "memory_analysis_prompt.txt", 
                "input_sections": ["memory"],
                "requires_previous": True,
                "chunkable": True,
                "priority": 3
            },
            {
                "section": "signatures_analysis",
                "prompt_file": "signatures_analysis_prompt.txt",
                "input_sections": ["signatures"],
                "requires_previous": True,
                "chunkable": False,
                "priority": 4
            },
            {
                "section": "behavior_analysis",
                "prompt_file": "behavior_analysis_initial_prompt.txt",
                "continuation_prompt": "behavior_analysis_continuation_prompt.txt",
                "input_sections": ["behavior"],
                "requires_previous": True,
                "chunkable": True,
                "priority": 5
            },
            {
                "section": "strings_analysis",
                "prompt_file": "strings_analysis_initial_prompt.txt", 
                "input_sections": ["strings"],
                "requires_previous": True,
                "chunkable": True,
                "priority": 6
            },
            {
                "section": "final_synthesis",
                "prompt_file": "final_synthesis_prompt.txt",
                "input_sections": ["all_ai_analyses"],
                "requires_previous": True,
                "chunkable": False,
                "priority": 7
            }
        ]

    def extract_json_from_response(self, ai_response: str) -> Any:
        """
        Enhanced JSON extraction with robust markdown and malformed JSON handling.
        Specifically designed to handle the behavior analysis JSON-in-markdown responses.
        """
        if not ai_response:
            return {"error": "Empty response from AI"}
        
        cleaned_response = ai_response.strip()
        
        # Try direct JSON parsing first (for properly formatted responses)
        try:
            return json.loads(cleaned_response)
        except json.JSONDecodeError:
            pass
        
        # Enhanced markdown code block extraction with multiple strategies
        json_patterns = [
            # Strategy 1: Complete JSON in markdown code blocks
            r'```json\s*(\{.*\})\s*```',
            r'```\s*(\{.*\})\s*```',
            
            # Strategy 2: JSON that might be truncated or malformed in markdown
            r'```json\s*(\{[\s\S]*?)\s*```',
            r'```\s*(\{[\s\S]*?)\s*```',
            
            # Strategy 3: Look for JSON object patterns (more flexible)
            r'(\{\s*"[^"]*"\s*:\s*[^}]*\})',
            
            # Strategy 4: Handle responses that start with JSON but have extra text
            r'^(\{[\s\S]*?\})(?:\n|$)',
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, cleaned_response, re.DOTALL | re.MULTILINE)
            for match in matches:
                if not match:
                    continue
                    
                try:
                    # Clean up the match
                    json_text = match.strip()
                    
                    # Handle common formatting issues
                    json_text = re.sub(r',\s*}', '}', json_text)  # Remove trailing commas
                    json_text = re.sub(r',\s*]', ']', json_text)  # Remove trailing commas in arrays
                    
                    # Balance braces if response was truncated
                    open_braces = json_text.count('{')
                    close_braces = json_text.count('}')
                    
                    if open_braces > close_braces:
                        json_text += '}' * (open_braces - close_braces)
                    
                    # Try to parse
                    parsed = json.loads(json_text)
                    print(f"✅ Successfully extracted JSON using pattern: {pattern[:50]}...")
                    return parsed
                    
                except json.JSONDecodeError as e:
                    print(f"❌ JSON extraction failed for pattern {pattern[:50]}: {str(e)[:100]}...")
                    continue
        
        # Strategy 5: If we have a substantial response that looks like analysis text
        # but couldn't be parsed as JSON, return it as structured text analysis
        if len(cleaned_response) > 300:
            print("⚠️  Falling back to text analysis for substantial response")
            
            # Try to extract key sections from the text response
            analysis_structure = self._structure_text_response(cleaned_response)
            
            if analysis_structure:
                return analysis_structure
            
            # Return as analysis text with parse warning
            return {
                "analysis_text": cleaned_response,
                "parse_warning": "AI response was not in expected JSON format but contains substantial analysis content",
                "response_length": len(cleaned_response),
                "sections_found": self._detect_sections_in_text(cleaned_response)
            }
        
        # Final fallback
        return {
            "error": "No valid JSON response from AI",
            "raw_response_preview": cleaned_response[:500] if cleaned_response else "Empty",
            "response_length": len(cleaned_response)
        }

    def _structure_text_response(self, text_response: str) -> Optional[Dict[str, Any]]:
        """
        Attempt to structure a text response into a semi-structured format.
        This is a fallback when JSON parsing fails but we have good analysis content.
        """
        try:
            # Look for common section patterns in behavior analysis
            sections = {}
            
            # Extract executive summary if present
            exec_match = re.search(r'(?:executive summary|overview|summary)[:\s]*([^\n].*?)(?=\n\n|\n[A-Z]|\Z)', 
                                 text_response, re.IGNORECASE | re.DOTALL)
            if exec_match:
                sections["executive_summary"] = {
                    "overview": exec_match.group(1).strip(),
                    "extracted_from_text": True
                }
            
            # Extract key behaviors
            behaviors_match = re.search(r'(?:key behaviors|key findings|behaviors)[:\s]*([^\n].*?)(?=\n\n|\n[A-Z]|\Z)', 
                                      text_response, re.IGNORECASE | re.DOTALL)
            if behaviors_match:
                behaviors_text = behaviors_match.group(1)
                # Try to extract bullet points or list items
                behaviors_list = re.findall(r'[•\-*]\s*([^\n]+)', behaviors_text)
                if behaviors_list:
                    sections["key_behaviors"] = behaviors_list
                else:
                    sections["key_behaviors"] = [behaviors_text.strip()]
            
            # Extract threat level
            threat_match = re.search(r'(?:threat level|threat activity level|risk level)[:\s]*([^\n]+)', 
                                   text_response, re.IGNORECASE)
            if threat_match:
                sections["threat_assessment"] = {
                    "level": threat_match.group(1).strip(),
                    "extracted_from_text": True
                }
            
            if sections:
                return {
                    **sections,
                    "structured_from_text": True,
                    "original_response_preview": text_response[:1000] + "..." if len(text_response) > 1000 else text_response
                }
            
            return None
            
        except Exception as e:
            print(f"Error structuring text response: {e}")
            return None

    def _detect_sections_in_text(self, text: str) -> List[str]:
        """Detect what sections are present in a text response"""
        sections_found = []
        section_keywords = {
            "executive_summary": ["executive", "summary", "overview"],
            "technical_analysis": ["technical", "analysis", "process", "api", "calls"],
            "mitre_attack": ["mitre", "attack", "technique", "tactics"],
            "recommendations": ["recommend", "suggest", "action", "response"]
        }
        
        lower_text = text.lower()
        for section, keywords in section_keywords.items():
            if any(keyword in lower_text for keyword in keywords):
                sections_found.append(section)
        
        return sections_found

    async def load_prompt(self, prompt_file: str) -> str:
        """Load prompt template from file"""
        prompt_path = self.templates_dir / prompt_file
        try:
            with open(prompt_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            raise Exception(f"Failed to load prompt {prompt_file}: {str(e)}")

    def prepare_section_data(self, parsed_results: Dict, section_names: List[str]) -> str:
        """Prepare section data for AI analysis"""
        if section_names == ["all"]:
            # Include all parsed sections for context-aware analysis
            section_data = {}
            for section_name, section_content in parsed_results["sections"].items():
                section_data[section_name] = section_content
            return json.dumps(section_data, indent=2)
        
        elif section_names == ["all_ai_analyses"]:
            # This will be handled separately with previous AI results
            return ""
        
        else:
            # Specific sections from parsed results
            section_data = {}
            for section_name in section_names:
                if section_name in parsed_results["sections"]:
                    section_data[section_name] = parsed_results["sections"][section_name]
            return json.dumps(section_data, indent=2)

    async def analyze_section_with_fallback(
        self, 
        section_config: Dict,
        parsed_results: Dict,
        previous_analyses: Dict,
        model_name: Optional[str] = None,
        analysis_id: str = None
    ) -> Dict[str, Any]:
        """Analyze a section with automatic model fallback and chunking support"""
        
        section_name = section_config["section"]
        print(f"🔍 Analyzing section: {section_name}")
        
        try:
            # Load appropriate prompt
            prompt_template = await self.load_prompt(section_config["prompt_file"])
            
            # Prepare input data
            input_data = self.prepare_section_data(parsed_results, section_config["input_sections"])
            
            # Build context from previous analyses
            context = self._build_analysis_context(previous_analyses, section_config)
            
            # Handle chunkable sections
            if section_config["chunkable"] and section_config["input_sections"][0] in parsed_results["sections"]:
                return await self._analyze_chunkable_section(
                    section_config, parsed_results, previous_analyses, 
                    prompt_template, context, model_name, analysis_id
                )
            else:
                # Standard non-chunkable section analysis
                return await self._analyze_standard_section(
                    section_config, prompt_template, input_data, context, 
                    model_name, analysis_id
                )
                
        except Exception as e:
            print(f"❌ Analysis failed for {section_name}: {str(e)}")
            return {
                "section": section_name,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "failed"
            }

    async def _analyze_chunkable_section(
        self,
        section_config: Dict,
        parsed_results: Dict,
        previous_analyses: Dict,
        prompt_template: str,
        context: str,
        model_name: str,
        analysis_id: str
    ) -> Dict[str, Any]:
        """Analyze sections that require chunking (behavior, strings, memory)"""
        
        section_name = section_config["section"]
        section_data = parsed_results["sections"][section_config["input_sections"][0]]
        
        # Get chunks based on section type
        if section_name == "behavior_analysis":
            chunks = self.chunking_service.chunk_behavior_data(section_data)
            continuation_prompt = await self.load_prompt(section_config["continuation_prompt"])
        elif section_name == "strings_analysis":
            chunks = self.chunking_service.chunk_strings_data(section_data)
            continuation_prompt = None
        elif section_name == "memory_analysis":
            chunks = self.chunking_service.chunk_memory_data(section_data)
            continuation_prompt = None
        else:
            chunks = [{"data": section_data, "chunk_info": {"current_chunk": 1, "total_chunks": 1}}]
            continuation_prompt = None
        
        print(f"📦 Processing {len(chunks)} chunks for {section_name}")
        
        chunk_results = []
        previous_chunk_analysis = None
        
        for chunk_idx, chunk in enumerate(chunks):
            chunk_info = chunk["chunk_info"]
            chunk_data = chunk["data"]
            
            print(f"   Chunk {chunk_info['current_chunk']}/{chunk_info['total_chunks']} "
                  f"({chunk_info.get('processes_in_chunk', chunk_info.get('strings_in_chunk', chunk_info.get('entries_in_chunk', 0)))} items)")
            
            # Use continuation prompt for subsequent behavior chunks
            if continuation_prompt and chunk_idx > 0:
                current_prompt = continuation_prompt
                chunk_context = self._build_chunk_context(previous_chunk_analysis, context)
            else:
                current_prompt = prompt_template
                chunk_context = context
            
            # Build chunk-specific prompt
            full_prompt = self._build_chunk_prompt(
                current_prompt, chunk_context, chunk_data, chunk_info, 
                section_name, previous_analyses
            )
            
            try:
                # Analyze chunk with fallback
                chunk_result = await self._call_model_with_fallback(
                    full_prompt, model_name, analysis_id, f"{section_name}_chunk_{chunk_info['current_chunk']}"
                )
                
                parsed_response = self.extract_json_from_response(chunk_result.get("response", ""))
                
                chunk_analysis = {
                    "chunk_number": chunk_info["current_chunk"],
                    "total_chunks": chunk_info["total_chunks"],
                    "chunk_info": chunk_info,
                    "analysis": parsed_response,
                    "ai_model": chunk_result.get("model"),
                    "timestamp": datetime.now().isoformat()
                }
                
                chunk_results.append(chunk_analysis)
                previous_chunk_analysis = chunk_analysis
                
                print(f"   ✅ Chunk {chunk_info['current_chunk']} completed")
                
                # Brief pause between chunks
                if chunk_idx < len(chunks) - 1:
                    await asyncio.sleep(1)
                    
            except Exception as e:
                print(f"   ❌ Chunk {chunk_info['current_chunk']} failed: {str(e)}")
                chunk_results.append({
                    "chunk_number": chunk_info["current_chunk"],
                    "total_chunks": chunk_info["total_chunks"],
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
                # Continue with next chunk even if one fails
        
        # Combine chunk results
        return {
            "section": section_name,
            "analysis_type": "chunked",
            "total_chunks": len(chunks),
            "chunks_analyzed": len([c for c in chunk_results if "analysis" in c]),
            "chunks_failed": len([c for c in chunk_results if "error" in c]),
            "chunk_results": chunk_results,
            "combined_analysis": self._combine_chunk_analyses(chunk_results),
            "timestamp": datetime.now().isoformat()
        }

    async def _analyze_standard_section(
        self,
        section_config: Dict,
        prompt_template: str,
        input_data: str,
        context: str,
        model_name: str,
        analysis_id: str
    ) -> Dict[str, Any]:
        """Analyze standard (non-chunkable) sections"""
        
        section_name = section_config["section"]
        
        # Build full prompt
        if context:
            full_prompt = f"{prompt_template}\n\n{context}\n\nANALYSIS DATA:\n{input_data}"
        else:
            full_prompt = f"{prompt_template}\n\nANALYSIS DATA:\n{input_data}"
        
        try:
            result = await self._call_model_with_fallback(full_prompt, model_name, analysis_id, section_name)
            
            parsed_response = self.extract_json_from_response(result.get("response", ""))
            
            return {
                "section": section_name,
                "analysis_type": "standard",
                "ai_model": result.get("model"),
                "analysis": parsed_response,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"❌ Standard analysis failed for {section_name}: {str(e)}")
            return {
                "section": section_name,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "failed"
            }

    async def _call_model_with_fallback(
        self, 
        prompt: str, 
        preferred_model: str, 
        analysis_id: str, 
        section_name: str
    ) -> Dict[str, Any]:
        """Call AI model with fallback mechanism"""
        
        models_to_try = []
        if preferred_model:
            models_to_try.append(preferred_model)
        
        # Add fallback models from enhanced model service
        if hasattr(self.model_service, 'fallback_priority'):
            models_to_try.extend([m for m in self.model_service.fallback_priority if m not in models_to_try])
        else:
            # Fallback to default models
            models_to_try.extend(["gemini-2.5-flash", "grok-4.1-fast-free", "llama-3.3-70b-free"])
        
        last_error = None
        for model_name in models_to_try:
            try:
                print(f"   🤖 Trying model: {model_name}")
                result = await self.model_service.process_request(
                    prompt=prompt,
                    model_name=model_name
                )
                
                # Validate response
                if result.get("response") and len(result["response"].strip()) > 50:
                    return result
                else:
                    raise Exception("Invalid or empty response from model")
                    
            except Exception as e:
                last_error = e
                print(f"   ❌ {model_name} failed: {str(e)[:100]}...")
                
                # If rate limited, wait before trying next model
                error_msg = str(e).lower()
                if any(keyword in error_msg for keyword in ['rate', 'quota', '429']):
                    print("   ⏳ Rate limited, waiting 3 seconds...")
                    await asyncio.sleep(3)
                
                continue
        
        raise Exception(f"All models failed for {section_name}. Last error: {last_error}")

    def _build_analysis_context(self, previous_analyses: Dict, section_config: Dict) -> str:
        """Build context from previous analyses"""
        if not section_config["requires_previous"] or not previous_analyses:
            return ""
        
        if section_config["section"] == "final_synthesis":
            return "PREVIOUS AI ANALYSES:\n" + json.dumps(previous_analyses, indent=2, default=str)
        else:
            # Include relevant previous analyses for context
            context_data = {}
            for prev_section, prev_analysis in previous_analyses.items():
                if "analysis" in prev_analysis:
                    context_data[prev_section] = prev_analysis["analysis"]
            
            return "ANALYSIS CONTEXT:\n" + json.dumps(context_data, indent=2, default=str) if context_data else ""

    def _build_chunk_context(self, previous_chunk_analysis: Dict, base_context: str) -> str:
        """Build context for continuation chunks"""
        if not previous_chunk_analysis:
            return base_context
        
        chunk_context = {
            "previous_chunk_analysis": previous_chunk_analysis.get("analysis", {}),
            "base_context": base_context
        }
        
        return "CONTINUATION CONTEXT:\n" + json.dumps(chunk_context, indent=2, default=str)

    def _build_chunk_prompt(
        self, 
        prompt_template: str, 
        context: str, 
        chunk_data: Dict, 
        chunk_info: Dict,
        section_name: str,
        previous_analyses: Dict
    ) -> str:
        """Build prompt for chunk analysis"""
        
        chunk_data_str = json.dumps(chunk_data, indent=2)
        
        # Add chunk-specific placeholders to prompt template
        enhanced_prompt = prompt_template.replace("{chunk_info}", json.dumps(chunk_info, indent=2))
        enhanced_prompt = enhanced_prompt.replace("{section_data}", chunk_data_str)
        
        if context:
            return f"{enhanced_prompt}\n\n{context}"
        else:
            return enhanced_prompt

    def _combine_chunk_analyses(self, chunk_results: List[Dict]) -> Dict[str, Any]:
        """Combine analyses from multiple chunks into a cohesive result"""
        successful_chunks = [chunk for chunk in chunk_results if "analysis" in chunk]
        
        if not successful_chunks:
            return {"error": "All chunks failed", "total_chunks": len(chunk_results)}
        
        # Basic combination - in practice, you might want more sophisticated merging
        combined = {
            "total_chunks_processed": len(successful_chunks),
            "chunks_failed": len(chunk_results) - len(successful_chunks),
            "summary": f"Analyzed {len(successful_chunks)} chunks successfully"
        }
        
        # For behavior analysis, you might combine process analyses
        # For strings analysis, you might combine string categories
        # This is a simplified version - extend based on your needs
        
        return combined

    async def progressive_analysis(
        self, 
        parsed_results: Dict,
        model_name: Optional[str] = None,
        output_dir: Path = None
    ) -> Dict[str, Any]:
        """Perform enhanced progressive analysis with chunking support"""
        
        print("🚀 Starting enhanced progressive AI analysis with chunking...")
        
        # Create analysis ID and output directory
        analysis_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        if not output_dir:
            output_dir = Path("temp_analysis_output") / analysis_id
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Analyze chunking requirements
        chunking_analysis = self.chunking_service.analyze_chunking_requirements(parsed_results)
        print(f"📊 Chunking analysis: {chunking_analysis}")
        
        # Store all analyses
        all_analyses = {}
        analysis_context = {}
        
        # Sort analysis plan by priority
        sorted_plan = sorted(self.analysis_plan, key=lambda x: x["priority"])
        
        # Track model usage
        model_usage = {}
        
        for section_config in sorted_plan:
            section_name = section_config["section"]
            print(f"\n{'='*50}")
            print(f"📊 Processing: {section_name}")
            print(f"{'='*50}")
            
            # Analyze section with chunking and fallback
            section_result = await self.analyze_section_with_fallback(
                section_config,
                parsed_results,
                analysis_context,
                model_name,
                analysis_id
            )
            
            # Track model usage
            if "ai_model" in section_result:
                model_used = section_result["ai_model"]
                model_usage[model_used] = model_usage.get(model_used, 0) + 1
            
            # Store results
            all_analyses[section_name] = section_result
            analysis_context[section_name] = section_result
            
            # Save individual result
            section_file = output_dir / f"{section_name}_analysis.json"
            with open(section_file, 'w', encoding='utf-8') as f:
                json.dump(section_result, f, indent=2, ensure_ascii=False, default=str)
            print(f"✅ Saved: {section_file.name}")
            
            # Brief pause between sections
            await asyncio.sleep(2)
        
        # Save combined results
        combined_file = output_dir / "all_analyses.json"
        with open(combined_file, 'w', encoding='utf-8') as f:
            json.dump(all_analyses, f, indent=2, ensure_ascii=False, default=str)
        
        # Save model usage stats
        usage_file = output_dir / "model_usage.json"
        with open(usage_file, 'w', encoding='utf-8') as f:
            json.dump(model_usage, f, indent=2, ensure_ascii=False)
        
        # Save analysis summary
        summary = {
            "analysis_id": analysis_id,
            "timestamp": datetime.now().isoformat(),
            "sections_analyzed": list(all_analyses.keys()),
            "model_usage": model_usage,
            "chunking_analysis": chunking_analysis,
            "output_directory": str(output_dir)
        }
        
        summary_file = output_dir / "analysis_summary.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        print(f"\n🎉 Enhanced progressive analysis completed!")
        print(f"📁 Output directory: {output_dir}")
        print(f"🤖 Models used: {model_usage}")
        print(f"📊 Sections analyzed: {len(all_analyses)}")
        
        return {
            "analysis_id": analysis_id,
            "output_directory": str(output_dir),
            "sections_analyzed": list(all_analyses.keys()),
            "model_usage": model_usage,
            "chunking_analysis": chunking_analysis,
            "results": all_analyses
        }


# Factory function for dependency injection
async def get_enhanced_analysis_service(
    model_service,
    parser_service, 
    chunking_service
):
    return EnhancedAnalysisService(model_service, parser_service, chunking_service)