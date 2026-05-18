# D:\FYP\ChameleonServer\app\services\robust_model_service.py
import asyncio
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from app.utils.logger import get_logger

_logger = get_logger("app.services.robust_model")


class RobustModelService:
    """
    Enhanced model service with sophisticated fallback logic, error recovery,
    and model performance tracking.
    """
    
    def __init__(self, enhanced_model_service):
        self.model_service = enhanced_model_service
        self.failure_tracker = {}  # Track model failures
        self.success_tracker = {}  # Track model successes
        self.rate_limit_tracker = {}  # Track rate limits
        self.model_performance = {}  # Track response times and quality
        
        # Model reliability scores (higher = more reliable)
        self.model_reliability = {}
        self._initialize_reliability_scores()
        
        # Fallback configuration
        self.fallback_config = {
            "max_retries_per_model": 2,
            "retry_delay_base": 2,  # seconds
            "rate_limit_cooldown": 30,  # seconds
            "max_total_attempts": 10,
            "response_timeout": 120,  # seconds
        }
        
        # Response quality thresholds
        self.quality_thresholds = {
            "min_response_length": 50,
            "max_error_keywords": ["error", "cannot", "unable", "sorry", "apologize"],
            "valid_json_required": False,  # Set to True if you require JSON responses
        }

    def _initialize_reliability_scores(self):
        """Initialize reliability scores for all available models"""
        available_models = self.model_service.get_available_models()
        free_models = self.model_service.get_free_models()
        
        # Start with higher scores for free models with large context
        for model in available_models:
            config = self.model_service.get_model_config(model)
            if config:
                # Base score on context length and free tier status
                base_score = config.get("context_length", 0) / 10000
                if config.get("free_tier", False):
                    base_score += 2.0
                if "gemini" in model.lower():
                    base_score += 1.0  # Prefer Gemini for reliability
                
                self.model_reliability[model] = max(1.0, base_score)

    async def process_request_with_enhanced_fallback(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
        preferred_model: Optional[str] = None,
        analysis_id: str = "unknown",
        section_name: str = "unknown",
        require_json: bool = False
    ) -> Dict[str, Any]:
        """
        Process request with enhanced fallback logic, error recovery, and quality checks.
        
        Args:
            prompt: The prompt to send to the AI model
            file_content: Optional file content
            filename: Optional filename
            preferred_model: Preferred model to try first
            analysis_id: ID for tracking this analysis
            section_name: Name of the section being analyzed
            require_json: Whether to require JSON response format
            
        Returns:
            Dictionary with response and metadata
        """
        _logger.info("Starting enhanced model request for %s (Analysis: %s)", section_name, analysis_id)
        
        # Update quality requirements if JSON is required
        current_quality = self.quality_thresholds.copy()
        if require_json:
            current_quality["valid_json_required"] = True
        
        # Get prioritized model list
        models_to_try = self._get_prioritized_models(preferred_model, analysis_id, section_name)
        
        total_attempts = 0
        last_valid_response = None
        best_model_used = None
        
        for model_name in models_to_try:
            if total_attempts >= self.fallback_config["max_total_attempts"]:
                break
                
            # Check if model is in cooldown due to rate limits
            if self._is_model_in_cooldown(model_name):
                _logger.info("%s in cooldown, skipping...", model_name)
                continue
            
            # Try this model with retries
            for attempt in range(self.fallback_config["max_retries_per_model"]):
                total_attempts += 1
                if total_attempts > self.fallback_config["max_total_attempts"]:
                    break
                    
                _logger.info("Attempt %d: %s (retry %d)", total_attempts, model_name, attempt + 1)
                
                try:
                    start_time = time.time()
                    
                    # Execute model request with timeout
                    result = await asyncio.wait_for(
                        self._execute_model_request(
                            model_name, prompt, file_content, filename, 
                            analysis_id, section_name
                        ),
                        timeout=self.fallback_config["response_timeout"]
                    )
                    
                    response_time = time.time() - start_time
                    
                    # Validate response quality
                    validation_result = self._validate_response_quality(
                        result, current_quality, model_name, section_name
                    )
                    
                    if validation_result["is_valid"]:
                        # Success! Track performance and return result
                        self._record_success(
                            model_name, analysis_id, section_name, 
                            response_time, validation_result["quality_score"]
                        )
                        
                        _logger.info(
                            "%s succeeded in %.2fs (quality: %.2f)",
                            model_name,
                            response_time,
                            validation_result["quality_score"],
                        )
                        
                        # Enhance result with metadata
                        enhanced_result = self._enhance_result_with_metadata(
                            result, model_name, analysis_id, section_name,
                            response_time, validation_result, total_attempts
                        )
                        
                        return enhanced_result
                    
                    else:
                        # Response failed quality check
                        quality_issue = validation_result["issues"][0] if validation_result["issues"] else "quality_check_failed"
                        raise Exception(f"Response quality issue: {quality_issue}")
                        
                except asyncio.TimeoutError:
                    error_msg = f"Request timeout after {self.fallback_config['response_timeout']}s"
                    self._record_failure(model_name, analysis_id, section_name, error_msg)
                    _logger.warning("%s timeout", model_name)
                    
                except Exception as e:
                    error_msg = str(e)
                    self._record_failure(model_name, analysis_id, section_name, error_msg)
                    
                    # Check error type and handle accordingly
                    if self._is_rate_limit_error(error_msg):
                        self._handle_rate_limit(model_name, error_msg)
                        _logger.warning("%s rate limited - cooldown activated", model_name)
                        break  # Don't retry this model immediately
                    elif self._is_model_loading_error(error_msg):
                        _logger.info("%s loading - will retry after delay", model_name)
                        await asyncio.sleep(10 * (attempt + 1))  # Longer delay for loading
                    else:
                        _logger.error("%s failed: %s", model_name, error_msg[:200])
                        await asyncio.sleep(self.fallback_config["retry_delay_base"] * (attempt + 1))
                
                # Update reliability score based on failure
                self._update_model_reliability(model_name, success=False)
        
        # If we get here, all models failed
        error_summary = self._generate_error_summary(analysis_id, section_name)
        
        # Return last valid response if available, otherwise raise error
        if last_valid_response:
                _logger.warning("All models failed, returning last valid response from %s", best_model_used)
            return last_valid_response
        
        raise Exception(f"All models failed for {section_name}. Error summary: {error_summary}")

    def _get_prioritized_models(self, preferred_model: Optional[str], analysis_id: str, section_name: str) -> List[str]:
        """Get models sorted by reliability and context requirements"""
        
        # Start with preferred model if specified
        models = []
        if preferred_model and preferred_model in self.model_service.get_available_models():
            models.append(preferred_model)
        
        # Add other models sorted by reliability score
        available_models = self.model_service.get_available_models()
        reliable_models = [
            model for model in available_models 
            if model not in models and not self._is_model_in_cooldown(model)
        ]
        
        # Sort by reliability score (descending)
        reliable_models.sort(key=lambda m: self.model_reliability.get(m, 1.0), reverse=True)
        
        models.extend(reliable_models)
        
        # Ensure we have models with sufficient context for large sections
        if section_name in ["behavior_analysis", "strings_analysis"]:
            models = self._prioritize_high_context_models(models)
        
        _logger.debug("Model priority for %s: %s...", section_name, models[:3])
        return models

    def _prioritize_high_context_models(self, models: List[str]) -> List[str]:
        """Prioritize models with larger context windows"""
        high_context_models = []
        standard_models = []
        
        for model in models:
            config = self.model_service.get_model_config(model)
            if config and config.get("context_length", 0) >= 100000:  # 100k+ tokens
                high_context_models.append(model)
            else:
                standard_models.append(model)
        
        return high_context_models + standard_models

    async def _execute_model_request(
        self,
        model_name: str,
        prompt: str,
        file_content: Optional[bytes],
        filename: Optional[str],
        analysis_id: str,
        section_name: str
    ) -> Dict[str, Any]:
        """Execute a single model request with error handling"""
        try:
            return await self.model_service.process_request(
                prompt=prompt,
                file_content=file_content,
                filename=filename,
                model_name=model_name
            )
        except Exception as e:
            # Enhance error message with context
            enhanced_error = f"{model_name} failed for {section_name}: {str(e)}"
            raise Exception(enhanced_error) from e

    def _validate_response_quality(
        self, 
        result: Dict[str, Any], 
        quality_thresholds: Dict, 
        model_name: str,
        section_name: str
    ) -> Dict[str, Any]:
        """Validate the quality of the AI response"""
        response = result.get("response", "").strip()
        issues = []
        quality_score = 0.0
        
        # Check response length
        if len(response) < quality_thresholds["min_response_length"]:
            issues.append(f"response_too_short_{len(response)}")
        
        # Check for error keywords
        lower_response = response.lower()
        error_keywords_found = [
            keyword for keyword in quality_thresholds["max_error_keywords"]
            if keyword in lower_response
        ]
        if error_keywords_found:
            issues.append(f"error_keywords_{','.join(error_keywords_found[:2])}")
        
        # Check for JSON validity if required
        if quality_thresholds["valid_json_required"]:
            try:
                json.loads(response)
                quality_score += 0.3  # Bonus for valid JSON
            except json.JSONDecodeError:
                # Try to extract JSON from markdown
                json_match = self._extract_json_from_markdown(response)
                if not json_match:
                    issues.append("invalid_json_format")
                else:
                    quality_score += 0.2  # Partial bonus for extracted JSON
        
        # Calculate quality score (0.0 to 1.0)
        base_score = min(1.0, len(response) / 1000)  # Longer responses generally better
        if not issues:
            quality_score += base_score
        else:
            quality_score += base_score * 0.5  # Penalty for issues
        
        # Section-specific quality checks
        section_quality = self._check_section_specific_quality(response, section_name)
        quality_score += section_quality * 0.2
        
        return {
            "is_valid": len(issues) == 0,
            "quality_score": min(1.0, quality_score),
            "issues": issues,
            "response_length": len(response)
        }

    def _check_section_specific_quality(self, response: str, section_name: str) -> float:
        """Perform section-specific quality checks"""
        score = 0.0
        lower_response = response.lower()
        
        if section_name == "behavior_analysis":
            # Behavior analysis should contain specific terms
            behavior_terms = ["process", "api", "injection", "registry", "network"]
            found_terms = [term for term in behavior_terms if term in lower_response]
            score = len(found_terms) / len(behavior_terms) * 0.5
        
        elif section_name == "signatures_analysis":
            # Signatures analysis should contain scoring or detection terms
            signature_terms = ["score", "detection", "malicious", "ttp", "mitre"]
            found_terms = [term for term in signature_terms if term in lower_response]
            score = len(found_terms) / len(signature_terms) * 0.5
        
        return score

    def _extract_json_from_markdown(self, text: str) -> Optional[Dict]:
        """Extract JSON from markdown code blocks"""
        import re
        json_patterns = [
            r'```json\s*(.*?)\s*```',
            r'```\s*(.*?)\s*```',
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, text, re.DOTALL)
            for match in matches:
                try:
                    return json.loads(match.strip())
                except json.JSONDecodeError:
                    continue
        return None

    def _is_rate_limit_error(self, error_msg: str) -> bool:
        """Check if error indicates rate limiting"""
        rate_limit_indicators = ['rate', 'quota', '429', 'too many', 'limit exceeded']
        return any(indicator in error_msg.lower() for indicator in rate_limit_indicators)

    def _is_model_loading_error(self, error_msg: str) -> bool:
        """Check if error indicates model is loading"""
        loading_indicators = ['loading', '503', 'unavailable', 'initializing']
        return any(indicator in error_msg.lower() for indicator in loading_indicators)

    def _is_model_in_cooldown(self, model_name: str) -> bool:
        """Check if model is in cooldown due to rate limits"""
        if model_name not in self.rate_limit_tracker:
            return False
        
        last_rate_limit = self.rate_limit_tracker[model_name]
        cooldown_end = last_rate_limit + timedelta(seconds=self.fallback_config["rate_limit_cooldown"])
        
        return datetime.now() < cooldown_end

    def _handle_rate_limit(self, model_name: str, error_msg: str):
        """Handle rate limit by putting model in cooldown"""
        self.rate_limit_tracker[model_name] = datetime.now()
        self._update_model_reliability(model_name, success=False, severe_failure=True)

    def _record_success(self, model_name: str, analysis_id: str, section_name: str, 
                       response_time: float, quality_score: float):
        """Record successful model usage"""
        # Update success tracker
        key = f"{model_name}_{section_name}"
        if key not in self.success_tracker:
            self.success_tracker[key] = []
        
        self.success_tracker[key].append({
            "timestamp": datetime.now(),
            "response_time": response_time,
            "quality_score": quality_score,
            "analysis_id": analysis_id
        })
        
        # Update performance metrics
        if model_name not in self.model_performance:
            self.model_performance[model_name] = {
                "total_requests": 0,
                "successful_requests": 0,
                "average_response_time": 0,
                "total_response_time": 0,
                "last_success": None
            }
        
        perf = self.model_performance[model_name]
        perf["total_requests"] += 1
        perf["successful_requests"] += 1
        perf["total_response_time"] += response_time
        perf["average_response_time"] = perf["total_response_time"] / perf["successful_requests"]
        perf["last_success"] = datetime.now()
        
        # Update reliability score
        self._update_model_reliability(model_name, success=True, response_time=response_time, quality_score=quality_score)

    def _record_failure(self, model_name: str, analysis_id: str, section_name: str, error_msg: str):
        """Record model failure"""
        key = f"{model_name}_{section_name}"
        if key not in self.failure_tracker:
            self.failure_tracker[key] = []
        
        self.failure_tracker[key].append({
            "timestamp": datetime.now(),
            "error": error_msg,
            "analysis_id": analysis_id
        })
        
        # Update performance metrics
        if model_name not in self.model_performance:
            self.model_performance[model_name] = {
                "total_requests": 0,
                "successful_requests": 0,
                "average_response_time": 0,
                "total_response_time": 0,
                "failure_count": 0
            }
        
        self.model_performance[model_name]["total_requests"] += 1
        self.model_performance[model_name]["failure_count"] = \
            self.model_performance[model_name].get("failure_count", 0) + 1

    def _update_model_reliability(self, model_name: str, success: bool, 
                                response_time: float = None, quality_score: float = None,
                                severe_failure: bool = False):
        """Update model reliability score"""
        current_score = self.model_reliability.get(model_name, 1.0)
        
        if success:
            # Increase score for success, more for faster responses and higher quality
            increase = 0.1
            if response_time and response_time < 10:  # Fast response bonus
                increase += 0.05
            if quality_score and quality_score > 0.8:  # High quality bonus
                increase += 0.05
            
            new_score = min(10.0, current_score + increase)
        else:
            # Decrease score for failure, more for severe failures
            decrease = 0.2 if severe_failure else 0.1
            new_score = max(0.1, current_score - decrease)
        
        self.model_reliability[model_name] = new_score

    def _enhance_result_with_metadata(
        self, 
        result: Dict[str, Any], 
        model_name: str,
        analysis_id: str,
        section_name: str,
        response_time: float,
        validation_result: Dict,
        total_attempts: int
    ) -> Dict[str, Any]:
        """Enhance result with metadata about the request"""
        return {
            **result,
            "metadata": {
                "model_used": model_name,
                "analysis_id": analysis_id,
                "section_name": section_name,
                "response_time_seconds": round(response_time, 2),
                "quality_score": validation_result["quality_score"],
                "total_attempts": total_attempts,
                "timestamp": datetime.now().isoformat(),
                "reliability_score": round(self.model_reliability.get(model_name, 1.0), 2)
            }
        }

    def _generate_error_summary(self, analysis_id: str, section_name: str) -> str:
        """Generate summary of errors for this analysis"""
        relevant_failures = []
        for key, failures in self.failure_tracker.items():
            if analysis_id in [f["analysis_id"] for f in failures] and section_name in key:
                relevant_failures.extend(failures)
        
        if not relevant_failures:
            return "No specific error information available"
        
        error_counts = {}
        for failure in relevant_failures:
            error_msg = failure["error"]
            error_type = error_msg.split(":")[0] if ":" in error_msg else error_msg
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
        
        return f"Errors: {', '.join([f'{k}({v})' for k, v in error_counts.items()])}"

    def get_model_stats(self) -> Dict[str, Any]:
        """Get statistics about model performance"""
        return {
            "model_reliability": self.model_reliability,
            "model_performance": self.model_performance,
            "failure_tracker_summary": {
                key: len(failures) for key, failures in self.failure_tracker.items()
            },
            "success_tracker_summary": {
                key: len(successes) for key, successes in self.success_tracker.items()
            }
        }

    def get_best_models(self, count: int = 5) -> List[Tuple[str, float]]:
        """Get the most reliable models"""
        sorted_models = sorted(
            self.model_reliability.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_models[:count]

    def reset_tracking(self):
        """Reset all tracking data (useful for testing)"""
        self.failure_tracker.clear()
        self.success_tracker.clear()
        self.rate_limit_tracker.clear()
        self.model_performance.clear()
        self._initialize_reliability_scores()


# Factory function for dependency injection
async def get_robust_model_service(enhanced_model_service):
    return RobustModelService(enhanced_model_service)