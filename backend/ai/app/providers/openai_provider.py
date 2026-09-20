"""OpenAI-compatible AI Provider using httpx with timeout and security controls."""

import json
import logging
from typing import Optional
import httpx
from .base import BaseAIProvider
from ..config import AIConfig

logger = logging.getLogger(__name__)


class OpenAIProvider(BaseAIProvider):
    """Client for OpenAI-compatible chat completion APIs."""

    def __init__(self, config: AIConfig):
        self.config = config
        self.api_key = config.api_key or ""
        self.base_url = (config.base_url or "https://api.openai.com/v1").rstrip("/")
        self.model = config.model
        self.timeout = config.timeout

    async def analyze(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Dispatches chat completion request to configured LLM endpoint."""
        if not self.api_key:
            logger.warning("No AI_API_KEY configured for OpenAI provider. Analysis will fail-closed.")
            return None

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                choices = data.get("choices", [])
                if choices and "message" in choices[0]:
                    return choices[0]["message"].get("content")
                return None
        except httpx.TimeoutException:
            logger.error(f"AI API request timed out after {self.timeout}s to {url}")
            return None
        except httpx.HTTPStatusError as e:
            logger.error(f"AI API returned HTTP error {e.response.status_code}: {e.response.text[:200]}")
            return None
        except Exception as e:
            logger.error(f"AI API request failed: {e}")
            return None
