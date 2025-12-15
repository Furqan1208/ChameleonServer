import asyncio
import json
import os
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from google import genai
from google.genai import types
from huggingface_hub import InferenceClient
from openai import OpenAI

from app.utils.api_key_pool import APIKeyPool

load_dotenv()


class ModelService:
    def __init__(self):
        self.default_model = os.getenv("DEFAULT_AI_MODEL", "gemini-2.5-flash")
        self.max_retries = int(os.getenv("MAX_RETRIES", "3"))
        self.timeout = int(os.getenv("REQUEST_TIMEOUT", "60"))

        self.gemini_clients = self._initialize_gemini_clients()
        # self.hf_client = self._initialize_huggingface_client()
        # self.openrouter_client = self._initialize_openrouter_client()

        self.model_configs = self._build_model_configs()
        self.fallback_priority = self._calculate_fallback_priority()

        # Initialize API key pool for Gemini
        self.gemini_pool = None
        if self.gemini_clients:
            self.gemini_pool = APIKeyPool(self.gemini_clients, max_concurrent_per_key=2)

        # Semaphores for other providers
        self.openrouter_semaphore = asyncio.Semaphore(3)
        self.huggingface_semaphore = asyncio.Semaphore(2)

    def _initialize_gemini_clients(self) -> List[genai.Client]:
        api_keys = self._get_gemini_api_keys()
        clients = []

        for idx, key in enumerate(api_keys):
            try:
                client = genai.Client(api_key=key)
                clients.append(client)
                print(f"Initialized Gemini client {idx + 1}")
            except Exception as e:
                print(f"Failed to initialize Gemini client {idx + 1}: {str(e)}")

        if not clients:
            print("Warning: No Gemini clients initialized")

        return clients

    def _get_gemini_api_keys(self) -> List[str]:
        keys = []

        primary_key = os.getenv("GEMINI_API_KEY")
        if primary_key:
            keys.append(primary_key)

        idx = 1
        while True:
            key = os.getenv(f"GEMINI_API_KEY_{idx}")
            if not key:
                break
            keys.append(key)
            idx += 1

        return keys

    # def _initialize_huggingface_client(self) -> Optional[InferenceClient]:
    #     token = os.getenv("HUGGINGFACE_TOKEN")
    #     if token:
    #         return InferenceClient(token=token)
    #     return None

    # def _initialize_openrouter_client(self) -> Optional[OpenAI]:
    #     api_key = os.getenv("OPENROUTER_API_KEY")
    #     if api_key:
    #         return OpenAI(api_key=api_key, base_url="https://openrouter.ai/api/v1")
    #     return None

    def _build_model_configs(self) -> Dict[str, Dict[str, Any]]:
        configs = {}

        if self.gemini_clients:
            configs.update(
                {
                    "gemini-2.5-flash": {
                        "provider": "gemini",
                        "model_name": "gemini-2.5-flash",
                        "clients": self.gemini_clients,
                        "context_length": 1000000,
                        "priority": 1,
                    },
                    "gemini-2.5-pro": {
                        "provider": "gemini",
                        "model_name": "gemini-2.5-pro",
                        "clients": self.gemini_clients,
                        "context_length": 2000000,
                        "priority": 2,
                    },
                    "gemini-2.0-flash": {
                        "provider": "gemini",
                        "model_name": "gemini-2.0-flash",
                        "clients": self.gemini_clients,
                        "context_length": 1000000,
                        "priority": 3,
                    },
                    "gemini-2.0-flash-lite": {
                        "provider": "gemini",
                        "model_name": "gemini-2.0-flash-lite",
                        "clients": self.gemini_clients,
                        "context_length": 1000000,
                        "priority": 4,
                    },
                }
            )

        # if self.openrouter_client:
        #     configs.update(
        #         {
        #             "grok-4.1-fast-free": {
        #                 "provider": "openrouter",
        #                 "model_name": "x-ai/grok-4.1-fast:free",
        #                 "client": self.openrouter_client,
        #                 "context_length": 2000000,
        #                 "priority": 1,
        #             },
        #             "grok-4.1-fast": {
        #                 "provider": "openrouter",
        #                 "model_name": "x-ai/grok-4.1-fast",
        #                 "client": self.openrouter_client,
        #                 "context_length": 2000000,
        #                 "priority": 2,
        #             },
        #             "gemini-2.0-flash-exp-free": {
        #                 "provider": "openrouter",
        #                 "model_name": "google/gemini-2.0-flash-exp:free",
        #                 "client": self.openrouter_client,
        #                 "context_length": 1048576,
        #                 "priority": 3,
        #             },
        #             "llama-3.3-70b-free": {
        #                 "provider": "openrouter",
        #                 "model_name": "meta-llama/llama-3.3-70b-instruct:free",
        #                 "client": self.openrouter_client,
        #                 "context_length": 131072,
        #                 "priority": 4,
        #             },
        #             "llama-3.2-3b-free": {
        #                 "provider": "openrouter",
        #                 "model_name": "meta-llama/llama-3.2-3b-instruct:free",
        #                 "client": self.openrouter_client,
        #                 "context_length": 131072,
        #                 "priority": 5,
        #             },
        #             "llama-3.1-8b-free": {
        #                 "provider": "openrouter",
        #                 "model_name": "meta-llama/llama-3.1-8b-instruct:free",
        #                 "client": self.openrouter_client,
        #                 "context_length": 131072,
        #                 "priority": 6,
        #             },
        #             "qwen-2.5-7b-free": {
        #                 "provider": "openrouter",
        #                 "model_name": "qwen/qwen-2.5-7b-instruct:free",
        #                 "client": self.openrouter_client,
        #                 "context_length": 32768,
        #                 "priority": 7,
        #             },
        #         }
        #     )

        # if self.hf_client:
        #     configs.update(
        #         {
        #             "MiniMaxAI": {
        #                 "provider": "huggingface",
        #                 "model_name": "MiniMaxAI/MiniMax-M2",
        #                 "client": self.hf_client,
        #                 "context_length": 32768,
        #                 "priority": 1,
        #             },
        #             "gpt-oss-20b": {
        #                 "provider": "huggingface",
        #                 "model_name": "openai/gpt-oss-20b",
        #                 "client": self.hf_client,
        #                 "context_length": 4096,
        #                 "priority": 2,
        #             },
        #             "llama-3.1-8b-hf": {
        #                 "provider": "huggingface",
        #                 "model_name": "meta-llama/Meta-Llama-3.1-8B-Instruct",
        #                 "client": self.hf_client,
        #                 "context_length": 131072,
        #                 "priority": 3,
        #             },
        #             "mistral-7b-hf": {
        #                 "provider": "huggingface",
        #                 "model_name": "mistralai/Mistral-7B-Instruct-v0.3",
        #                 "client": self.hf_client,
        #                 "context_length": 32768,
        #                 "priority": 4,
        #             },
        #             "phi-3-mini": {
        #                 "provider": "huggingface",
        #                 "model_name": "microsoft/Phi-3-mini-4k-instruct",
        #                 "client": self.hf_client,
        #                 "context_length": 4096,
        #                 "priority": 5,
        #             },
        #         }
        #     )

        return configs

    def _calculate_fallback_priority(self) -> List[str]:
        available_models = [
            (name, config)
            for name, config in self.model_configs.items()
            if self._has_valid_client(config)
        ]
        available_models.sort(key=lambda x: x[1].get("priority", 999))
        return [name for name, _ in available_models]

    def _has_valid_client(self, config: Dict[str, Any]) -> bool:
        if "clients" in config:
            return len(config["clients"]) > 0
        return config.get("client") is not None

    async def process_request(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
        model_name: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Process a request with parallel support.

        Args:
            prompt: The prompt to send
            file_content: Optional file content
            filename: Optional filename
            model_name: Model to use
            task_id: Optional task identifier for logging
        """
        model_to_use = model_name or self.default_model

        if model_to_use not in self.model_configs:
            raise ValueError(f"Model {model_to_use} not supported")

        config = self.model_configs[model_to_use]

        if not self._has_valid_client(config):
            raise ValueError(f"No API key configured for {model_to_use}")

        full_prompt = self._prepare_prompt(prompt, file_content, filename)

        provider = config["provider"]
        if provider == "gemini":
            return await self._call_gemini_parallel(config, full_prompt, task_id)
        # elif provider == "openrouter":
        #     async with self.openrouter_semaphore:
        #         return await self._call_openrouter(config, full_prompt)
        # elif provider == "huggingface":
        #     async with self.huggingface_semaphore:
        #         return await self._call_huggingface(config, full_prompt)
        else:
            raise ValueError(f"Unknown provider: {provider}")

    async def _call_gemini_parallel(
        self, config: Dict[str, Any], prompt: str, task_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Call Gemini API using key pool for parallel requests.
        """
        if not self.gemini_pool:
            # Fallback to original method if pool not initialized
            return await self._call_gemini_with_fallback(config, prompt)

        model_name = config["model_name"]
        max_attempts = 3

        for attempt in range(max_attempts):
            key_idx, client = await self.gemini_pool.acquire_key()

            try:
                task_label = f"[{task_id}] " if task_id else ""
                print(
                    f"{task_label}Using Gemini key {key_idx + 1} (attempt {attempt + 1})"
                )

                response = await asyncio.to_thread(
                    client.models.generate_content,
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.2,
                        max_output_tokens=8192,
                    ),
                )

                await self.gemini_pool.release_key(key_idx, success=True)

                return {
                    "response": response.text,
                    "model": model_name,
                    "api_key_index": key_idx + 1,
                }

            except Exception as e:
                error_msg = str(e).lower()
                is_rate_limit = any(
                    keyword in error_msg
                    for keyword in ["rate", "quota", "429", "resource_exhausted"]
                )

                await self.gemini_pool.release_key(key_idx, success=False)

                if is_rate_limit and attempt < max_attempts - 1:
                    wait_time = 2**attempt
                    print(f"Rate limited on key {key_idx + 1}, waiting {wait_time}s...")
                    await asyncio.sleep(wait_time)
                    continue
                elif not is_rate_limit:
                    # Non-rate-limit error, raise immediately
                    raise

        raise Exception("All attempts failed for parallel Gemini request")

    async def _call_gemini_with_fallback(
        self, config: Dict[str, Any], prompt: str
    ) -> Dict[str, Any]:
        """Original sequential fallback method."""
        clients = config["clients"]
        model_name = config["model_name"]

        last_error = None

        for client_idx, client in enumerate(clients):
            print(f"Trying Gemini API key {client_idx + 1}/{len(clients)}")

            for attempt in range(self.max_retries):
                try:
                    response = await asyncio.to_thread(
                        client.models.generate_content,
                        model=model_name,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            temperature=0.2,
                            max_output_tokens=8192,
                        ),
                    )

                    print(f"Success with Gemini API key {client_idx + 1}")

                    return {
                        "response": response.text,
                        "model": model_name,
                        "api_key_index": client_idx + 1,
                    }

                except Exception as e:
                    last_error = e
                    error_msg = str(e).lower()

                    is_rate_limit = any(
                        keyword in error_msg
                        for keyword in ["rate", "quota", "429", "resource_exhausted"]
                    )

                    if is_rate_limit:
                        if attempt < self.max_retries - 1:
                            wait_time = 2**attempt
                            print(
                                f"Rate limited on key {client_idx + 1}, attempt {attempt + 1}. Waiting {wait_time}s..."
                            )
                            await asyncio.sleep(wait_time)
                            continue
                        else:
                            print(
                                f"Rate limited on key {client_idx + 1}, moving to next key"
                            )
                            break
                    else:
                        raise

            if client_idx < len(clients) - 1:
                await asyncio.sleep(1)

        raise Exception(f"All Gemini API keys exhausted. Last error: {last_error}")

    # async def _call_openrouter(
    #     self, config: Dict[str, Any], prompt: str
    # ) -> Dict[str, Any]:
    #     client = config["client"]
    #     model_name = config["model_name"]

    #     last_error: Optional[Exception] = None

    #     for attempt in range(self.max_retries):
    #         try:
    #             response = await asyncio.to_thread(
    #                 client.chat.completions.create,
    #                 model=model_name,
    #                 messages=[{"role": "user", "content": prompt}],
    #                 max_tokens=4096,
    #                 temperature=0.7,
    #             )

    #             return {
    #                 "response": response.choices[0].message.content,
    #                 "model": model_name,
    #                 "usage": {
    #                     "prompt_tokens": response.usage.prompt_tokens,
    #                     "completion_tokens": response.usage.completion_tokens,
    #                     "total_tokens": response.usage.total_tokens,
    #                 }
    #                 if response.usage
    #                 else {},
    #             }

    #         except Exception as e:
    #             last_error = e

    #             if self._should_retry(e, attempt):
    #                 wait_time = 2**attempt
    #                 print(f"OpenRouter rate limited. Waiting {wait_time}s...")
    #                 await asyncio.sleep(wait_time)
    #                 continue

    #             raise

    #     raise Exception(
    #         f"OpenRouter request failed after {self.max_retries} attempts: {last_error}"
    #     )

    # async def _call_huggingface(
    #     self, config: Dict[str, Any], prompt: str
    # ) -> Dict[str, Any]:
    #     client = config["client"]
    #     model_name = config["model_name"]

    #     last_error: Optional[Exception] = None

    #     for attempt in range(self.max_retries):
    #         try:
    #             response = await asyncio.to_thread(
    #                 client.chat.completions.create,
    #                 model=model_name,
    #                 messages=[{"role": "user", "content": prompt}],
    #             )

    #             msg = response.choices[0].message
    #             result = (
    #                 msg.get("content")
    #                 if isinstance(msg, dict)
    #                 else getattr(msg, "content", None)
    #             )

    #             if not result:
    #                 raise Exception(
    #                     "HuggingFace returned empty or invalid response content"
    #                 )

    #             return {
    #                 "response": result,
    #                 "model": model_name,
    #             }

    #         except Exception as e:
    #             last_error = e

    #             if self._should_retry(e, attempt):
    #                 wait_time = 5 * (attempt + 1)
    #                 print(f"HuggingFace model loading. Waiting {wait_time}s...")
    #                 await asyncio.sleep(wait_time)
    #                 continue

    #             raise

    #     raise Exception(
    #         f"HuggingFace request failed after {self.max_retries} attempts: {last_error}"
    #     )

    def _prepare_prompt(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> str:
        if not file_content:
            return prompt

        file_text = self._prepare_file_content(file_content, filename)
        if file_text:
            return f"{prompt}\n\n{file_text}"
        return prompt

    def _prepare_file_content(
        self, file_content: Optional[bytes], filename: Optional[str]
    ) -> Optional[str]:
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

        except UnicodeDecodeError as e:
            raise ValueError("Unable to decode file as UTF-8 text.") from e

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

    def _should_retry(self, error: Exception, attempt: int) -> bool:
        error_msg = str(error).lower()
        retry_conditions = [
            attempt < self.max_retries - 1,
            any(
                keyword in error_msg
                for keyword in ["rate", "quota", "429", "503", "loading"]
            ),
        ]
        return all(retry_conditions)

    def get_available_models(self) -> List[str]:
        return list(self.model_configs.keys())

    def get_model_config(self, model_name: str) -> Optional[Dict[str, Any]]:
        return self.model_configs.get(model_name)

    def get_models_by_context_length(self, min_context: int = 0) -> List[str]:
        models = [
            (name, config)
            for name, config in self.model_configs.items()
            if config.get("context_length", 0) >= min_context
            and self._has_valid_client(config)
        ]
        models.sort(key=lambda x: x[1].get("context_length", 0), reverse=True)
        return [name for name, _ in models]

    def get_api_key_stats(self) -> Dict:
        """Get statistics about API key usage."""
        stats = {}
        if self.gemini_pool:
            stats["gemini"] = self.gemini_pool.get_stats()
        return stats
