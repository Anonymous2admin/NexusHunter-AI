"""Comprehensive unit and integration test suite for NexusHunter-AI Security Analysis Engine."""

import pytest
from datetime import datetime, timezone

from app.config import AIConfig, validate_base_url
from app.evidence import EvidenceSanitizer, EvidenceCollector
from app.models import CandidateState, FindingCategory, SeverityHint
from app.schemas import (
    StructuredEvidence,
    ServiceEvidence,
    TechnologyEvidence,
    SecurityObservationEvidence,
    URLEvidence,
)
from app.detectors.reflection import ReflectionDetector
from app.detectors.idor_auth import IDORAuthDetector
from app.detectors.ssrf import SSRFDetector
from app.detectors.injection import InjectionAnomalyDetector
from app.detectors.concurrency import ConcurrencyDetector
from app.detectors.info_disclosure import InfoDisclosureDetector
from app.analyzer import SecurityAnalyzer
from app.providers.mock import MockAIProvider


def test_config_ssrf_protection():
    """Verify SSRF validation blocks private IP ranges and localhost in custom base URLs."""
    with pytest.raises(ValueError):
        validate_base_url("http://127.0.0.1:8000")

    with pytest.raises(ValueError):
        validate_base_url("http://localhost:5000")

    with pytest.raises(ValueError):
        validate_base_url("http://10.0.0.1:8080")

    with pytest.raises(ValueError):
        validate_base_url("http://192.168.1.1")

    with pytest.raises(ValueError):
        validate_base_url("http://169.254.169.254/latest/meta-data")

    # Valid public HTTPS domain should pass
    assert validate_base_url("https://api.openai.com/v1") == "https://api.openai.com/v1"


def test_evidence_sanitizer():
    """Verify sensitive authorization headers, bearer tokens, and passwords are redacted."""
    headers = {
        "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sometoken.sig",
        "cookie": "session_id=secret_cookie_12345; user=alice",
        "x-api-key": "secret-api-key-999",
        "content-type": "application/json"
    }
    sanitized = EvidenceSanitizer.sanitize_headers(headers)
    assert "[REDACTED]" in sanitized["authorization"]
    assert "[REDACTED]" in sanitized["cookie"]
    assert "[REDACTED]" in sanitized["x-api-key"]
    assert sanitized["content-type"] == "application/json"

    # Test URL query param redaction
    url = "https://example.com/api?token=secret123&password=supersecret&search=test"
    sanitized_url = EvidenceSanitizer.sanitize_url(url)
    assert "token=%5BREDACTED%5D" in sanitized_url or "token=[REDACTED]" in sanitized_url
    assert "password=%5BREDACTED%5D" in sanitized_url or "password=[REDACTED]" in sanitized_url
    assert "search=test" in sanitized_url


def test_evidence_collector():
    """Verify evidence items are cleanly compiled with SHA-256 integrity hashes."""
    evidence = StructuredEvidence(
        target_id="tgt-1",
        asset_id="ast-1",
        service=ServiceEvidence(
            url="https://app.example.com",
            status_code=200,
            headers={"server": "nginx/1.24"},
            body_snippet="Welcome to the secure portal"
        ),
        technologies=[
            TechnologyEvidence(technology_name="React", category="Frontend", confidence="HIGH", version="18.2.0")
        ],
        security_observations=[
            SecurityObservationEvidence(property_name="Strict-Transport-Security", is_present=True, raw_value="max-age=31536000")
        ]
    )

    collector = EvidenceCollector()
    items = collector.collect(evidence)
    assert len(items) >= 3
    for item in items:
        assert len(item.sha256) == 64  # Valid SHA-256 hex


def test_reflection_detector():
    """Verify ReflectionDetector identifies reflected parameters in passive responses."""
    detector = ReflectionDetector()
    evidence = StructuredEvidence(
        target_id="target-1",
        asset_id="asset-1",
        service=ServiceEvidence(
            url="https://app.example.com/search?q=myqueryterm",
            status_code=200,
            headers={},
            body_snippet="<div>Search results for: myqueryterm</div>"
        )
    )
    signals = detector.detect("target-1", "asset-1", evidence)
    assert len(signals) == 1
    assert signals[0].signal_type == "REFLECTION_INDICATOR"
    assert "myqueryterm" in signals[0].evidence


def test_idor_auth_detector():
    """Verify IDORAuthDetector identifies sequential and UUID identifiers."""
    detector = IDORAuthDetector()
    evidence = StructuredEvidence(
        target_id="target-1",
        asset_id="asset-1",
        service=ServiceEvidence(
            url="https://app.example.com/api/users/12345/profile",
            status_code=200,
            headers={},
            body_snippet=""
        ),
        urls=[
            URLEvidence(url="https://app.example.com/orders?id=9876")
        ]
    )
    signals = detector.detect("target-1", "asset-1", evidence)
    assert len(signals) >= 2
    types = [s.signal_type for s in signals]
    assert "OBJECT_IDENTIFIER_DETECTED" in types


def test_ssrf_detector():
    """Verify SSRFDetector identifies URL-destination parameters."""
    detector = SSRFDetector()
    evidence = StructuredEvidence(
        target_id="target-1",
        asset_id="asset-1",
        service=ServiceEvidence(
            url="https://app.example.com/api/proxy?url=https://remote.server/data",
            status_code=200,
            headers={},
            body_snippet=""
        )
    )
    signals = detector.detect("target-1", "asset-1", evidence)
    assert len(signals) >= 1
    assert signals[0].signal_type == "POTENTIAL_SERVER_SIDE_REQUEST"
    assert signals[0].details["parameter"] == "url"


def test_injection_anomaly_detector():
    """Verify InjectionAnomalyDetector detects database errors in response snippets."""
    detector = InjectionAnomalyDetector()
    evidence = StructuredEvidence(
        target_id="target-1",
        asset_id="asset-1",
        service=ServiceEvidence(
            url="https://app.example.com/items",
            status_code=500,
            headers={},
            body_snippet="Internal Server Error: syntax error at or near 'LIMIT' in query SELECT * FROM items"
        )
    )
    signals = detector.detect("target-1", "asset-1", evidence)
    assert len(signals) == 1
    assert signals[0].signal_type == "POTENTIAL_INPUT_HANDLING_ANOMALY"
    assert signals[0].details["technology_hint"] == "postgresql"


def test_concurrency_detector():
    """Verify ConcurrencyDetector identifies transactional routes."""
    detector = ConcurrencyDetector()
    evidence = StructuredEvidence(
        target_id="target-1",
        asset_id="asset-1",
        service=ServiceEvidence(
            url="https://app.example.com/api/coupon/apply",
            status_code=200,
            headers={},
            body_snippet=""
        )
    )
    signals = detector.detect("target-1", "asset-1", evidence)
    assert len(signals) == 1
    assert signals[0].signal_type == "POTENTIAL_CONCURRENCY_SENSITIVE_ENDPOINT"


def test_info_disclosure_detector():
    """Verify InfoDisclosureDetector detects exposed sensitive routes and RFC1918 IPs."""
    detector = InfoDisclosureDetector()
    evidence = StructuredEvidence(
        target_id="target-1",
        asset_id="asset-1",
        service=ServiceEvidence(
            url="https://app.example.com",
            status_code=200,
            headers={"server": "Apache/2.4.52 (Ubuntu)"},
            body_snippet="Routed via internal gateway at 10.240.0.15"
        ),
        urls=[
            URLEvidence(url="https://app.example.com/actuator/health")
        ]
    )
    signals = detector.detect("target-1", "asset-1", evidence)
    assert len(signals) >= 2
    types = [s.signal_type for s in signals]
    assert "POTENTIAL_INFORMATION_EXPOSURE" in types


@pytest.mark.asyncio
async def test_security_analyzer_pipeline():
    """Verify full end-to-end analyzer execution respects the invariant: ALWAYS CANDIDATE."""
    provider = MockAIProvider()
    analyzer = SecurityAnalyzer(provider=provider)

    evidence = StructuredEvidence(
        target_id="target-123",
        asset_id="asset-456",
        service=ServiceEvidence(
            url="https://app.example.com/search?q=testinput",
            status_code=200,
            headers={"server": "nginx"},
            body_snippet="Results for testinput"
        )
    )

    result = await analyzer.analyze("target-123", "asset-456", evidence)

    assert result.target_id == "target-123"
    assert result.asset_id == "asset-456"
    assert len(result.signals) > 0
    assert len(result.candidates) > 0

    for cand in result.candidates:
        # Crucial Invariant: The AI must never skip to confirmed vulnerability
        assert cand.state == CandidateState.ANALYSIS_CANDIDATE
        assert cand.missing_evidence != ""
        assert len(cand.validation_steps) > 0
        assert len(cand.evidence_references) > 0
