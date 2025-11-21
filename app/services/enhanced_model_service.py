# D:\FYP\ChameleonServer\app\services\enhanced_model_service.py
import asyncio
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv
from google import genai
from google.genai import types
from huggingface_hub import InferenceClient
from openai import OpenAI

load_dotenv()


class EnhancedModelService:
    def __init__(self):
        self.default_model = os.getenv("DEFAULT_AI_MODEL", "gemini-2.5-flash")
        
        # Initialize clients
        self.gemini_client = None
        if os.getenv("GEMINI_API_KEY"):
            self.gemini_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

        self.hf_client = None
        if os.getenv("HUGGINGFACE_TOKEN"):
            self.hf_client = InferenceClient(token=os.getenv("HUGGINGFACE_TOKEN"))

        self.openrouter_client = None
        if os.getenv("OPENROUTER_API_KEY"):
            self.openrouter_client = OpenAI(
                api_key=os.getenv("OPENROUTER_API_KEY"),
                base_url="https://openrouter.ai/api/v1",
            )

        # Comprehensive free models configuration
        self.model_configs = {
            # ========== GEMINI MODELS ==========
            "gemini-2.5-flash": {
                "provider": "gemini",
                "model_name": "gemini-2.5-flash",
                "client": self.gemini_client,
                "context_length": 1000000,
                "free_tier": True,
                "priority": 1
            },
            "gemini-2.5-pro": {
                "provider": "gemini", 
                "model_name": "gemini-2.5-pro",
                "client": self.gemini_client,
                "context_length": 2000000,
                "free_tier": True,
                "priority": 2
            },
            "gemini-2.0-flash": {
                "provider": "gemini",
                "model_name": "gemini-2.0-flash",
                "client": self.gemini_client,
                "context_length": 1000000,
                "free_tier": True,
                "priority": 3
            },
            "gemini-2.0-flash-lite": {
                "provider": "gemini",
                "model_name": "gemini-2.0-flash-lite", 
                "client": self.gemini_client,
                "context_length": 1000000,
                "free_tier": True,
                "priority": 4
            },
            
            # ========== OPENROUTER FREE MODELS ==========
            "grok-4.1-fast-free": {
                "provider": "openrouter",
                "model_name": "x-ai/grok-4.1-fast:free",
                "client": self.openrouter_client,
                "context_length": 2000000,  # 2M context!
                "free_tier": True,
                "priority": 1
            },
            "grok-4.1-fast": {
                "provider": "openrouter", 
                "model_name": "x-ai/grok-4.1-fast",
                "client": self.openrouter_client,
                "context_length": 2000000,
                "free_tier": False,
                "priority": 2
            },
            "gemini-2.0-flash-exp-free": {
                "provider": "openrouter",
                "model_name": "google/gemini-2.0-flash-exp:free",
                "client": self.openrouter_client, 
                "context_length": 1048576,  # 1M context
                "free_tier": True,
                "priority": 3
            },
            "llama-3.3-70b-free": {
                "provider": "openrouter",
                "model_name": "meta-llama/llama-3.3-70b-instruct:free",
                "client": self.openrouter_client,
                "context_length": 131072,
                "free_tier": True,
                "priority": 4
            },
            "llama-3.2-3b-free": {
                "provider": "openrouter",
                "model_name": "meta-llama/llama-3.2-3b-instruct:free",
                "client": self.openrouter_client,
                "context_length": 131072,
                "free_tier": True, 
                "priority": 5
            },
            "llama-3.1-8b-free": {
                "provider": "openrouter",
                "model_name": "meta-llama/llama-3.1-8b-instruct:free",
                "client": self.openrouter_client,
                "context_length": 131072,
                "free_tier": True,
                "priority": 6
            },
            "qwen-2.5-7b-free": {
                "provider": "openrouter",
                "model_name": "qwen/qwen-2.5-7b-instruct:free",
                "client": self.openrouter_client,
                "context_length": 32768,
                "free_tier": True,
                "priority": 7
            },
            
            # ========== HUGGINGFACE MODELS ==========
            "MiniMaxAI": {
                "provider": "huggingface",
                "model_name": "MiniMaxAI/MiniMax-M2",
                "client": self.hf_client,
                "context_length": 32768,
                "free_tier": True,
                "priority": 1
            },
            "gpt-oss-20b": {
                "provider": "huggingface",
                "model_name": "openai/gpt-oss-20b", 
                "client": self.hf_client,
                "context_length": 4096,
                "free_tier": True,
                "priority": 2
            },
            "llama-3.1-8b-hf": {
                "provider": "huggingface",
                "model_name": "meta-llama/Meta-Llama-3.1-8B-Instruct",
                "client": self.hf_client,
                "context_length": 131072,
                "free_tier": True,
                "priority": 3
            },
            "mistral-7b-hf": {
                "provider": "huggingface", 
                "model_name": "mistralai/Mistral-7B-Instruct-v0.3",
                "client": self.hf_client,
                "context_length": 32768,
                "free_tier": True,
                "priority": 4
            },
            "phi-3-mini": {
                "provider": "huggingface",
                "model_name": "microsoft/Phi-3-mini-4k-instruct",
                "client": self.hf_client,
                "context_length": 4096,
                "free_tier": True,
                "priority": 5
            }
        }

        self.max_retries = int(os.getenv("MAX_RETRIES", "3"))
        self.timeout = int(os.getenv("REQUEST_TIMEOUT", "60"))
        
        # Model fallback priority (highest to lowest)
        self.fallback_priority = self._get_fallback_priority()

    def _get_fallback_priority(self) -> List[str]:
        """Get models sorted by priority for fallback"""
        free_models = [
            (name, config) for name, config in self.model_configs.items() 
            if config.get("free_tier", False) and config["client"] is not None
        ]
        # Sort by priority (lower number = higher priority)
        free_models.sort(key=lambda x: x[1].get("priority", 999))
        return [name for name, _ in free_models]

    async def process_request_with_fallback(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
        preferred_model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process request with automatic model fallback"""
        
        models_to_try = []
        if preferred_model and preferred_model in self.model_configs:
            models_to_try.append(preferred_model)
        
        # Add fallback models
        models_to_try.extend([m for m in self.fallback_priority if m not in models_to_try])
        
        last_error = None
        for model_name in models_to_try:
            print(f"🔄 Trying model: {model_name}")
            
            try:
                result = await self.process_request(
                    prompt=prompt,
                    file_content=file_content,
                    filename=filename,
                    model_name=model_name
                )
                print(f"✅ Success with {model_name}")
                return result
                
            except Exception as e:
                last_error = e
                error_msg = str(e)
                print(f"❌ {model_name} failed: {error_msg[:100]}...")
                
                # If it's a rate limit, wait before trying next model
                if any(keyword in error_msg.lower() for keyword in ['rate', 'quota', '429']):
                    print("⏳ Rate limited, waiting 5 seconds...")
                    await asyncio.sleep(5)
                
                continue
        
        # All models failed
        raise Exception(f"All models failed. Last error: {last_error}")

    async def process_request(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
        model_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        model_to_use = model_name or self.default_model

        if model_to_use not in self.model_configs:
            raise ValueError(f"Model {model_to_use} not supported")

        config = self.model_configs[model_to_use]

        if not config["client"]:
            raise ValueError(f"API key not configured for {model_to_use}")

        full_prompt = self._prepare_prompt(prompt, file_content, filename)

        provider = config["provider"]
        if provider == "gemini":
            return await self._call_gemini(config, full_prompt)
        elif provider == "openrouter":
            return await self._call_openrouter(config, full_prompt)
        elif provider == "huggingface":
            return await self._call_huggingface(config, full_prompt)
        else:
            raise ValueError(f"Unknown provider: {provider}")

    def _prepare_prompt(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> str:
        """Prepare full prompt with optional file content."""
        if not file_content:
            return prompt

        file_text = self._prepare_file_content(file_content, filename)
        if file_text:
            return f"{prompt}\n\n{file_text}"
        return prompt

    def _prepare_file_content(
        self, file_content: Optional[bytes], filename: Optional[str]
    ) -> Optional[str]:
        """Decode and prepare file content for text-based files."""
        if not file_content:
            return None

        try:
            content_str = file_content.decode("utf-8")
            file_type = self._get_file_type(filename)

            if file_type == "json":
                try:
                    json_data = json.loads(content_str)
                    formatted_content = json.dumps(json_data, indent=2)
                    return f"**JSON File Content:**\n```json\n{formatted_content}\n```"
                except json.JSONDecodeError:
                    return f"**JSON File Content (Raw):**\n```\n{content_str}\n```"
            elif file_type == "markdown":
                return f"**Markdown File Content:**\n{content_str}"
            else:
                return f"**Text File Content:**\n```\n{content_str}\n```"

        except UnicodeDecodeError:
            raise ValueError("Unable to decode file as UTF-8 text.")

    def _get_file_type(self, filename: Optional[str]) -> str:
        if not filename:
            return "text"
        filename_lower = filename.lower()
        if filename_lower.endswith(".json"):
            return "json"
        elif filename_lower.endswith(".md"):
            return "markdown"
        else:
            return "text"

    async def _call_gemini(self, config: Dict[str, Any], prompt: str) -> Dict[str, Any]:
        for attempt in range(self.max_retries):
            try:
                response = await asyncio.to_thread(
                    config["client"].models.generate_content,
                    model=config["model_name"],
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.7,
                        max_output_tokens=8192,
                    ),
                )
                return {
                    "response": response.text,
                    "model": config["model_name"],
                }
            except Exception as e:
                if self._should_retry(e, attempt):
                    wait_time = 2 ** attempt
                    print(f"Rate limited. Waiting {wait_time}s before retry...")
                    await asyncio.sleep(wait_time)
                    continue
                raise

    async def _call_openrouter(self, config: Dict[str, Any], prompt: str) -> Dict[str, Any]:
        for attempt in range(self.max_retries):
            try:
                response = await asyncio.to_thread(
                    config["client"].chat.completions.create,
                    model=config["model_name"],
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=4096,
                    temperature=0.7,
                )
                return {
                    "response": response.choices[0].message.content,
                    "model": config["model_name"],
                    "usage": {
                        "prompt_tokens": response.usage.prompt_tokens,
                        "completion_tokens": response.usage.completion_tokens,
                        "total_tokens": response.usage.total_tokens,
                    } if response.usage else {},
                }
            except Exception as e:
                if self._should_retry(e, attempt):
                    wait_time = 2 ** attempt
                    print(f"Rate limited. Waiting {wait_time}s before retry...")
                    await asyncio.sleep(wait_time)
                    continue
                raise

    async def _call_huggingface(self, config: Dict[str, Any], prompt: str) -> Dict[str, Any]:
        for attempt in range(self.max_retries):
            try:
                response = await asyncio.to_thread(
                    config["client"].chat.completions.create,
                    model=config["model_name"],
                    messages=[{"role": "user", "content": prompt}],
                )
                result = response.choices[0].message["content"]
                return {
                    "response": result,
                    "model": config["model_name"],
                }
            except Exception as e:
                if self._should_retry(e, attempt):
                    wait_time = 5 * (attempt + 1)
                    print(f"Model loading. Waiting {wait_time}s before retry...")
                    await asyncio.sleep(wait_time)
                    continue
                raise

    def _should_retry(self, error: Exception, attempt: int) -> bool:
        """Check if we should retry based on error type"""
        error_msg = str(error).lower()
        retry_conditions = [
            attempt < self.max_retries - 1,
            any(keyword in error_msg for keyword in ['rate', 'quota', '429', '503', 'loading'])
        ]
        return all(retry_conditions)

    def get_available_models(self) -> List[str]:
        return list(self.model_configs.keys())

    def get_model_config(self, model_name: str) -> Optional[Dict[str, Any]]:
        return self.model_configs.get(model_name)

    def get_free_models(self) -> List[str]:
        """Get list of free tier models"""
        return [name for name, config in self.model_configs.items() 
                if config.get("free_tier", False) and config["client"] is not None]

    def get_models_by_context_length(self, min_context: int = 0) -> List[str]:
        """Get models sorted by context length (descending)"""
        models = [(name, config) for name, config in self.model_configs.items()
                 if config.get("context_length", 0) >= min_context and config["client"] is not None]
        models.sort(key=lambda x: x[1].get("context_length", 0), reverse=True)
        return [name for name, _ in models]