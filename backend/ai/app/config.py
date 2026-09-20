"""Configuration module for NexusHunter-AI Security Analysis Engine."""

import ipaddress
import os
from typing import Optional
from urllib.parse import urlparse
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def validate_base_url(url: str) -> str:
    """Validates base URL against loopback, private subnets, and cloud metadata targets."""
    clean_url = url.strip()
    parsed = urlparse(clean_url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        raise ValueError("Invalid URL: hostname is empty")

    blocked_hosts = [
        "169.254.169.254",  # Cloud instance metadata
        "metadata.google.internal",
        "100.100.100.200",  # Alibaba metadata
        "::ffff:169.254.169.254",
        "localhost",
    ]
    for blocked in blocked_hosts:
        if blocked in hostname:
            raise ValueError(f"Prohibited AI_BASE_URL target detected: {blocked}")

    # Check if hostname is an IP address and check if it is private/loopback/link-local
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError(f"Prohibited private/loopback IP in AI_BASE_URL: {ip}")
    except ValueError as e:
        if "Prohibited" in str(e):
            raise e
        # hostname is a domain name, which is allowed if not matching blocked hosts

    return clean_url


class AIConfig(BaseSettings):
    """Runtime configuration for AI analysis service with strict boundaries."""

    # Provider configuration
    ai_provider: str = Field(default="mock", alias="AI_PROVIDER")
    ai_model: str = Field(default="gpt-4o-mini", alias="AI_MODEL")
    ai_api_key: Optional[str] = Field(default=None, alias="AI_API_KEY")
    ai_base_url: str = Field(default="https://api.openai.com/v1", alias="AI_BASE_URL")
    ai_timeout: float = Field(default=30.0, alias="AI_TIMEOUT")

    # Rate limiting & cost control bounds
    max_ai_requests_per_minute: int = Field(default=60, alias="MAX_AI_REQUESTS_PER_MINUTE")
    max_tokens_per_analysis: int = Field(default=4000, alias="MAX_TOKENS_PER_ANALYSIS")
    max_concurrent_analyses: int = Field(default=5, alias="MAX_CONCURRENT_ANALYSES")

    # Input guardrails
    max_evidence_items: int = Field(default=50, alias="MAX_EVIDENCE_ITEMS")
    max_text_length: int = Field(default=8192, alias="MAX_TEXT_LENGTH")
    max_request_body_bytes: int = Field(default=1_048_576, alias="MAX_REQUEST_BODY_BYTES")  # 1MB

    # Service configuration
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8001, alias="PORT")
    debug: bool = Field(default=False, alias="DEBUG")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def provider(self) -> str:
        return self.ai_provider

    @property
    def model(self) -> str:
        return self.ai_model

    @property
    def api_key(self) -> Optional[str]:
        return self.ai_api_key

    @property
    def base_url(self) -> str:
        return self.ai_base_url

    @property
    def timeout(self) -> float:
        return self.ai_timeout

    @property
    def rate_limit_rpm(self) -> int:
        return self.max_ai_requests_per_minute

    @field_validator("ai_base_url")
    @classmethod
    def validate_base_url_ssrf(cls, v: str) -> str:
        """Prevent SSRF attacks through arbitrary private cloud metadata URLs."""
        return validate_base_url(v)

    @field_validator("ai_provider")
    @classmethod
    def normalize_provider(cls, v: str) -> str:
        provider = v.strip().lower()
        if provider not in ("mock", "openai", "gemini", "azure", "none"):
            raise ValueError(f"Unsupported AI_PROVIDER: {provider}. Allowed: 'mock', 'openai', 'gemini', 'none'")
        return provider


# Global singleton configuration accessor
def get_config() -> AIConfig:
    return AIConfig()
