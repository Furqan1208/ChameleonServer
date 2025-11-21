# D:\FYP\ChameleonServer\app\services\enhanced_analysis_service.py
import json
import asyncio
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime


class EnhancedAnalysisService:
    def __init__(self, model_service, parser_service):
        self.model_service = model_service
        self.parser_service = parser_service
        self.templates_dir = Path("app/templates/section_prompts")
        
        # Section to prompt mapping with your parsed sections
        self.section_prompts = {
            "executive_summary": {
                "prompt_file": "01_executive_summary.md",
                "input_sections": ["info", "target"],
                "requires_previous": False
            },
            "target_analysis": {
                "prompt_file": "02_target_analysis.md", 
                "input_sections": ["target"],
                "requires_previous": False
            },
            "behavioral_analysis": {
                "prompt_file": "03_behavioral_analysis.md",
                "input_sections": ["behavior"],
                "requires_previous": False
            },
            "signatures_ttps": {
                "prompt_file": "04_signatures_ttps.md",
                "input_sections": ["signatures"],
                "requires_previous": False
            },
            "memory_analysis": {
                "prompt_file": "05_memory_analysis.md", 
                "input_sections": ["memory"],
                "requires_previous": False
            },
            "ioc_extraction": {
                "prompt_file": "06_ioc_extraction.md",
                "input_sections": ["all"],
                "requires_previous": True
            },
            "risk_assessment": {
                "prompt_file": "07_risk_assessment.md",
                "input_sections": ["all"],
                "requires_previous": True
            },
            "final_synthesis": {
                "prompt_file": "08_final_synthesis.md",
                "input_sections": ["all_ai_analyses"],
                "requires_previous": True
            }
        }

    def extract_json_from_response(self, ai_response: str) -> Any:
        """Extract JSON from AI response, handling markdown code blocks"""
        if not ai_response:
            return {"error": "Empty response from AI"}
        
        # Clean the response
        cleaned_response = ai_response.strip()
        
        # Try direct JSON parsing first
        try:
            return json.loads(cleaned_response)
        except json.JSONDecodeError:
            pass
        
        # Try to extract JSON from markdown code blocks
        json_patterns = [
            r'```json\s*(.*?)\s*```',  # ```json { ... } ```
            r'```\s*(.*?)\s*```',      # ``` { ... } ```
            r'\{.*\}',                 # Raw JSON object
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, cleaned_response, re.DOTALL)
            for match in matches:
                try:
                    return json.loads(match.strip())
                except json.JSONDecodeError:
                    continue
        
        # If no JSON found but we have content, return it as analysis
        if cleaned_response:
            return {
                "analysis_text": cleaned_response,
                "parse_warning": "AI response was not in expected JSON format"
            }
        
        return {"error": "No valid response from AI"}

    async def load_prompt(self, prompt_name: str) -> str:
        """Load prompt template from file"""
        prompt_config = self.section_prompts[prompt_name]
        prompt_file = self.templates_dir / prompt_config["prompt_file"]
        try:
            with open(prompt_file, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            raise Exception(f"Failed to load prompt {prompt_name}: {str(e)}")

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

    async def analyze_section(self, 
                           prompt_name: str, 
                           parsed_results: Dict,
                           previous_analyses: Dict,
                           model_name: Optional[str] = None) -> Dict[str, Any]:
        """Analyze a specific section with AI"""
        print(f"🔍 Analyzing section: {prompt_name}")
        
        # Load the prompt template
        prompt_template = await self.load_prompt(prompt_name)
        
        # Prepare input data from parsed sections
        section_config = self.section_prompts[prompt_name]
        input_data = self.prepare_section_data(parsed_results, section_config["input_sections"])
        
        # Build context from previous analyses if needed
        context = ""
        if section_config["requires_previous"] and previous_analyses:
            if prompt_name == "final_synthesis":
                # For final synthesis, use all previous AI analyses
                context = "PREVIOUS AI ANALYSES:\n" + json.dumps(previous_analyses, indent=2)
            else:
                # For other sections, use relevant parsed data context
                context = "ANALYSIS CONTEXT:\n" + json.dumps(previous_analyses, indent=2)
        
        # Build final prompt
        if context:
            full_prompt = f"{prompt_template}\n\n{context}\n\nANALYSIS DATA:\n{input_data}"
        else:
            full_prompt = f"{prompt_template}\n\nANALYSIS DATA:\n{input_data}"
        
        # Call AI model using your existing model_service
        try:
            result = await self.model_service.process_request(
                prompt=full_prompt,
                model_name=model_name
            )
            
            # Parse JSON response from AI with enhanced extraction
            ai_response = result.get("response", "")
            parsed_response = self.extract_json_from_response(ai_response)
            
            return {
                "section": prompt_name,
                "ai_model": result.get("model"),
                "analysis": parsed_response,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"❌ AI analysis failed for {prompt_name}: {str(e)}")
            return {
                "section": prompt_name,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    async def progressive_analysis(self, 
                                parsed_results: Dict,
                                model_name: Optional[str] = None,
                                output_dir: Path = None) -> Dict[str, Any]:
        """Perform progressive analysis on parsed results"""
        print("🚀 Starting progressive AI analysis...")
        
        # Create output directory
        if not output_dir:
            analysis_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            output_dir = Path("temp_analysis_output") / analysis_id
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Store all AI analyses
        ai_analyses = {}
        all_results = {}
        
        # Analysis order (progressive - builds context)
        analysis_order = [
            "executive_summary",    # info + target
            "target_analysis",      # target only  
            "behavioral_analysis",  # behavior only
            "signatures_ttps",      # signatures only
            "memory_analysis",      # memory only
            "ioc_extraction",       # all sections + previous context
            "risk_assessment",      # all sections + previous context
            "final_synthesis"       # all AI analyses
        ]
        
        # Execute analyses in order
        for section_name in analysis_order:
            print(f"\n📊 Processing: {section_name}")
            
            # Analyze section with progressive context
            section_result = await self.analyze_section(
                section_name,
                parsed_results,
                ai_analyses,  # Previous analyses as context
                model_name
            )
            
            # Store result
            ai_analyses[section_name] = section_result
            all_results[section_name] = section_result
            
            # Save individual section result
            section_file = output_dir / f"{section_name}_ai_analysis.json"
            with open(section_file, 'w', encoding='utf-8') as f:
                json.dump(section_result, f, indent=2, ensure_ascii=False)
            print(f"✅ Saved: {section_file.name}")
            
            # Brief pause between analyses to avoid rate limits
            await asyncio.sleep(2)
        
        # Save combined results
        combined_file = output_dir / "all_ai_analyses.json"
        with open(combined_file, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        
        print(f"\n🎉 Progressive analysis completed!")
        print(f"📁 Output directory: {output_dir}")
        
        return {
            "analysis_id": output_dir.name,
            "output_directory": str(output_dir),
            "sections_analyzed": list(all_results.keys()),
            "results": all_results
        }