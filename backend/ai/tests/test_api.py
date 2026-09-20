"""API endpoint tests for FastAPI AI Analysis service."""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "nexushunter-ai-analysis"
    assert "provider" in data
    assert "model" in data


def test_signals_endpoint():
    payload = {
        "target_id": "tgt-100",
        "asset_id": "ast-200",
        "evidence": {
            "target_id": "tgt-100",
            "asset_id": "ast-200",
            "service": {
                "url": "https://test.local/search?q=myreflectedtext",
                "status_code": 200,
                "body_snippet": "<div>Search term: myreflectedtext</div>"
            },
            "technologies": [],
            "security_observations": [],
            "urls": []
        }
    }
    response = client.post("/api/v1/signals", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target_id"] == "tgt-100"
    assert data["asset_id"] == "ast-200"
    assert data["count"] > 0
    signal_types = [s["signal_type"] for s in data["signals"]]
    assert "REFLECTION_INDICATOR" in signal_types


def test_analyze_endpoint():
    payload = {
        "target_id": "tgt-100",
        "asset_id": "ast-200",
        "run_id": "run-test-1",
        "evidence": {
            "target_id": "tgt-100",
            "asset_id": "ast-200",
            "service": {
                "url": "https://test.local/api/users/12345/details",
                "status_code": 200,
                "body_snippet": "{\"id\": 12345, \"email\": \"user@example.com\"}"
            },
            "technologies": [],
            "security_observations": [],
            "urls": [
                {"url": "https://test.local/api/users/12346/details"}
            ]
        }
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target_id"] == "tgt-100"
    assert data["asset_id"] == "ast-200"
    assert len(data["signals"]) > 0
    assert len(data["candidates"]) > 0
    for cand in data["candidates"]:
        # Verify candidate invariant
        assert cand["state"] == "CANDIDATE"
        assert len(cand["validation_steps"]) > 0
