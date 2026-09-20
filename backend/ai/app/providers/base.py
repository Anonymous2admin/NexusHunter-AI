"""Abstract base class for AI Model Providers."""

from abc import ABC, abstractmethod
from typing import Optional


class BaseAIProvider(ABC):
    """Abstract interface for LLM interaction."""

    @abstractmethod
    async def analyze(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Calls the configured LLM and returns the raw string response (expected to be JSON)."""
        pass
