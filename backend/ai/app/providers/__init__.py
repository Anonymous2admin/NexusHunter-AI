"""Provider factory for AI analysis engine."""

from .base import BaseAIProvider
from .mock import MockAIProvider
from .openai_provider import OpenAIProvider
from ..config import AIConfig


def get_ai_provider(config: AIConfig) -> BaseAIProvider:
    """Returns the appropriate AI provider instance based on environment configuration."""
    provider_name = config.provider.lower().strip()
    if provider_name in ("openai", "gemini", "azure"):
        return OpenAIProvider(config)
    return MockAIProvider()


__all__ = [
    "BaseAIProvider",
    "MockAIProvider",
    "OpenAIProvider",
    "get_ai_provider",
]
