import asyncio
import json
import os
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from google import genai
from google.genai import types
from huggingface_hub import InferenceClient
from openai import OpenAI

load_dotenv()


class ModelService:
    def __init__(self):
        self.default_model = os.getenv("DEFAULT_AI_MODEL", "gemini-2.5-flash")
        self.enabled_models = os.getenv("ENABLED_MODELS", "gemini-2.5-flash").split(",")

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

        self.model_configs = {
            "gemini-2.5-flash": {
                "provider": "gemini",
                "model_name": "gemini-2.5-flash",
                "client": self.gemini_client,
            },
            "gemini-2.5-pro": {
                "provider": "gemini",
                "model_name": "gemini-2.5-pro",
                "client": self.gemini_client,
            },
            "llama-3.1-8b": {
                "provider": "openrouter",
                "model_name": "meta-llama/llama-3.1-8b-instruct:free",
                "client": self.openrouter_client,
            },
            "llama-3.2-3b": {
                "provider": "openrouter",
                "model_name": "meta-llama/llama-3.2-3b-instruct:free",
                "client": self.openrouter_client,
            },
            "mistral-7b": {  # empty response
                "provider": "openrouter",
                "model_name": "mistralai/mistral-7b-instruct:free",
                "client": self.openrouter_client,
            },
            "MiniMaxAI": {
                "provider": "huggingface",
                "model_name": "MiniMaxAI/MiniMax-M2",
                "client": self.hf_client,
            },
            "gpt-oss-20b": {
                "provider": "huggingface",
                "model_name": "openai/gpt-oss-20b",
                "client": self.hf_client,
            },
        }

        self.max_retries = int(os.getenv("MAX_RETRIES", "3"))
        self.timeout = int(os.getenv("REQUEST_TIMEOUT", "60"))

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

    async def process_multi_model_batch(
        self, requests: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Process one request per model in parallel."""
        tasks = []
        for request in requests:
            model = request.get("model", self.default_model)
            if model not in self.enabled_models:
                model = self.default_model

            task = self.process_request(
                prompt=request["prompt"],
                file_content=request.get("file_content"),
                filename=request.get("filename"),
                model_name=model,
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed_results = []
        for result in results:
            if isinstance(result, BaseException):
                raise result
            processed_results.append(result)

        return processed_results

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
        """
        Decode and prepare file content for text-based files (JSON, TXT, MD).
        Returns formatted string with file type identification.
        """
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

            else:  # text file
                return f"**Text File Content:**\n```\n{content_str}\n```"

        except UnicodeDecodeError as exc:
            raise ValueError(
                "Unable to decode file as UTF-8 text. Expected JSON, TXT, or MD file."
            ) from exc

    def _get_file_type(self, filename: Optional[str]) -> str:
        """Determine file type from filename extension."""
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
        """Call Gemini API using official SDK."""
        for attempt in range(self.max_retries):
            try:
                response = await asyncio.to_thread(
                    config["client"].models.generate_content,
                    model=config["model_name"],
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.7,
                        max_output_tokens=8192,  # can remove limitations
                    ),
                )

                return {
                    "response": response.text,
                    "model": config["model_name"],
                }
            except Exception as e:
                if "429" in str(e) or "quota" in str(e).lower():
                    if attempt < self.max_retries - 1:
                        wait_time = 2**attempt
                        print(f"Rate limited. Waiting {wait_time}s before retry...")
                        await asyncio.sleep(wait_time)
                        continue
                if attempt == self.max_retries - 1:
                    raise Exception(f"Gemini API call failed: {str(e)}") from e
                await asyncio.sleep(1)

        raise Exception("Max retries exceeded")

    async def _call_openrouter(
        self, config: Dict[str, Any], prompt: str
    ) -> Dict[str, Any]:
        """Call OpenRouter API using OpenAI SDK."""
        for attempt in range(self.max_retries):
            try:
                response = await asyncio.to_thread(
                    config["client"].chat.completions.create,
                    model=config["model_name"],
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=4096,  # can remove limitations
                    temperature=0.7,
                )

                return {
                    "response": response.choices[0].message.content,
                    "model": config["model_name"],
                    "usage": {
                        "prompt_tokens": response.usage.prompt_tokens,
                        "completion_tokens": response.usage.completion_tokens,
                        "total_tokens": response.usage.total_tokens,
                    }
                    if response.usage
                    else {},
                }
            except Exception as e:
                if "429" in str(e) or "rate_limit" in str(e).lower():
                    if attempt < self.max_retries - 1:
                        wait_time = 2**attempt
                        print(f"Rate limited. Waiting {wait_time}s before retry...")
                        await asyncio.sleep(wait_time)
                        continue
                if attempt == self.max_retries - 1:
                    raise Exception(f"OpenRouter API call failed: {str(e)}") from e
                await asyncio.sleep(1)

        raise Exception("Max retries exceeded")

    async def _call_huggingface(
        self, config: Dict[str, Any], prompt: str
    ) -> Dict[str, Any]:
        """Call Hugging Face API using official SDK."""
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
                if "503" in str(e) or "loading" in str(e).lower():
                    if attempt < self.max_retries - 1:
                        wait_time = 5 * (attempt + 1)  # HF models may need loading time
                        print(f"Model loading. Waiting {wait_time}s before retry...")
                        await asyncio.sleep(wait_time)
                        continue
                if attempt == self.max_retries - 1:
                    raise Exception(f"Hugging Face API call failed: {str(e)}") from e
                await asyncio.sleep(1)

        raise Exception("Max retries exceeded")

    def get_available_models(self) -> List[str]:
        """Return list of available model names."""
        return list(self.model_configs.keys())

    def get_model_config(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get configuration for a specific model."""
        return self.model_configs.get(model_name)
