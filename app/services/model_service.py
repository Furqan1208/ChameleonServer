import asyncio
import base64
import os
from typing import Any, Dict, List, Optional

import aiohttp
from dotenv import load_dotenv

load_dotenv()


class ModelService:
    def __init__(self):
        self.default_model = os.getenv("DEFAULT_AI_MODEL", "gpt-3.5-turbo")
        self.enabled_models = os.getenv("ENABLED_MODELS", "gpt-3.5-turbo").split(",")
        self.model_configs = {
            "gpt-3.5-turbo": {
                "api_url": "https://api.openai.com/v1/chat/completions",
                "headers": {"Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}"},
                "payload_template": self._build_openai_payload,
            },
            "gemini": {
                "api_url": "https://generativelanguage.googleapis.com/v1/models/gemini-1.5-pro:generateContent",
                "headers": {"x-goog-api-key": os.getenv("GOOGLE_API_KEY")},
                "payload_template": self._build_gemini_payload,
            },
            "llama": {
                "api_url": "https://api.together.xyz/inference",
                "headers": {"Authorization": f"Bearer {os.getenv('TOGETHER_API_KEY')}"},
                "payload_template": self._build_llama_payload,
            },
            "mistral": {
                "api_url": "https://api.mistral.ai/v1/chat/completions",
                "headers": {"Authorization": f"Bearer {os.getenv('MISTRAL_API_KEY')}"},
                "payload_template": self._build_mistral_payload,
            },
            "deepseek": {
                "api_url": "https://api.openrouter.ai/api/v1/chat/completions",
                "headers": {
                    "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY')}"
                },
                "payload_template": self._build_deepseek_payload,
            },
            "qwen": {
                "api_url": "https://api-inference.huggingface.co/models/Qwen/Qwen-14B-Chat",
                "headers": {
                    "Authorization": f"Bearer {os.getenv('HUGGINGFACE_TOKEN')}"
                },
                "payload_template": self._build_qwen_payload,
            },
            "phi3": {
                "api_url": "https://api.azure.com/v1/deployments/phi-3/chat/completions",
                "headers": {"api-key": os.getenv("AZURE_API_KEY")},
                "payload_template": self._build_phi3_payload,
            },
        }

        self.max_retries = int(os.getenv("MAX_RETRIES", "3"))
        self.timeout = int(os.getenv("REQUEST_TIMEOUT", "30"))

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
        payload = config["payload_template"](prompt, file_content, filename)

        return await self._make_api_call(config, payload, file_content, filename)

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

    async def _make_api_call(
        self,
        config: Dict[str, Any],
        payload: Dict[str, Any],
        file_content: Optional[bytes],
        filename: Optional[str],
    ) -> Dict[str, Any]:
        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    timeout = aiohttp.ClientTimeout(total=self.timeout)

                    if file_content:
                        form_data = aiohttp.FormData()
                        for key, value in payload.items():
                            if isinstance(value, str):
                                form_data.add_field(key, value)
                            else:
                                form_data.add_field(key, value, filename=filename)

                        async with session.post(
                            config["api_url"],
                            headers=config["headers"],
                            data=form_data,
                            timeout=timeout,
                        ) as response:
                            result = await response.json()
                    else:
                        async with session.post(
                            config["api_url"],
                            headers=config["headers"],
                            json=payload,
                            timeout=timeout,
                        ) as response:
                            result = await response.json()

                    if response.status == 200:
                        return self._parse_response(config, result)
                    elif response.status == 429:
                        await asyncio.sleep(2**attempt)
                        continue
                    else:
                        raise Exception(f"API error: {result}")

            except asyncio.TimeoutError as e:
                if attempt == self.max_retries - 1:
                    raise Exception("Request timeout") from e
                continue
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise Exception(f"API call failed: {str(e)}") from e
                continue

        raise Exception("Max retries exceeded")

    def _build_openai_payload(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        messages: List[Dict[str, Any]] = [{"role": "user", "content": prompt}]

        if file_content:
            messages[0]["content"] = [
                {"type": "text", "text": prompt},
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/jpeg;base64,{file_content}"},
                },
            ]

        return {
            "model": "gpt-4-vision-preview",
            "messages": messages,
            "max_tokens": 1000,
        }

    def _build_gemini_payload(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        content: Dict[str, Any] = {"contents": [{"parts": [{"text": prompt}]}]}
        if file_content:
            # encode bytes to base64 string so the payload values are all strings
            file_b64 = base64.b64encode(file_content).decode("utf-8")
            content["contents"][0]["parts"].append(
                {
                    "inline_data": {
                        "mime_type": self._get_media_type(filename),
                        "data": file_b64,
                    }
                }
            )
        return content

    def _build_llama_payload(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "model": "meta-llama/Llama-3.1-70b-chat",
            "prompt": prompt,
            "max_tokens": 1000,
        }

    def _build_mistral_payload(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "model": "mistral-nemo",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1000,
        }

    def _build_deepseek_payload(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "model": "deepseek/deepseek-v3",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1000,
        }

    def _build_qwen_payload(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {"inputs": prompt}

    def _build_phi3_payload(
        self,
        prompt: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1000,
        }

    def _parse_response(self, config: Dict[str, Any], response: Any) -> Dict[str, Any]:
        api_url = config["api_url"]

        if "openai.com" in api_url:
            return {
                "response": response["choices"][0]["message"]["content"],
                "model": "gpt-3.5-turbo",
            }
        elif "googleapis.com" in api_url:
            return {
                "response": response["candidates"][0]["content"]["parts"][0]["text"],
                "model": "gemini",
            }
        elif "together.xyz" in api_url:
            return {"response": response["output"]["text"], "model": "llama"}
        elif "mistral.ai" in api_url:
            return {
                "response": response["choices"][0]["message"]["content"],
                "model": "mistral",
            }
        elif "openrouter.ai" in api_url:
            return {
                "response": response["choices"][0]["message"]["content"],
                "model": "deepseek",
            }
        elif "huggingface.co" in api_url:
            return {"response": response[0]["generated_text"], "model": "qwen"}
        elif "azure.com" in api_url:
            return {
                "response": response["choices"][0]["message"]["content"],
                "model": "phi3",
            }
        else:
            return {"response": response}

    def _get_media_type(self, filename: Optional[str]) -> str:
        if not filename:
            return "text/plain"

        extensions = {
            ".txt": "text/plain",
            ".md": "text/markdown",
            ".json": "application/json",
            ".py": "text/x-python",
            ".js": "text/javascript",
            ".html": "text/html",
            ".css": "text/css",
            ".xml": "application/xml",
            ".yaml": "application/x-yaml",
            ".yml": "application/x-yaml",
        }

        for ext, media_type in extensions.items():
            if filename.lower().endswith(ext):
                return media_type
        return "text/plain"

    def get_available_models(self) -> List[str]:
        return list(self.model_configs.keys())

    def get_model_config(self, model_name: str) -> Optional[Dict[str, Any]]:
        return self.model_configs.get(model_name)
