"""FastAPI Entrypoint for NexusHunter-AI Security Analysis Service."""

import logging
import time
from typing import Dict
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import AIConfig
from .analyzer import SecurityAnalyzer
from .schemas import StructuredEvidence
from .models import AnalysisResult, SecuritySignal

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("nexushunter.ai")

config = AIConfig()
analyzer = SecurityAnalyzer(config)

app = FastAPI(
    title="NexusHunter-AI Analysis Service",
    version="1.0.0",
    description="Deterministic and AI-assisted security signal & candidate analysis engine"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiter state
_request_counts: Dict[str, list] = {}


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Enforces MAX_AI_REQUESTS_PER_MINUTE per client IP."""
    if request.url.path.startswith("/api/v1/analyze"):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        timestamps = _request_counts.setdefault(client_ip, [])
        # Prune timestamps older than 60 seconds
        _request_counts[client_ip] = [t for t in timestamps if now - t < 60]
        if len(_request_counts[client_ip]) >= config.rate_limit_rpm:
            logger.warning(f"Rate limit exceeded for IP {client_ip} ({len(_request_counts[client_ip])} req/min)")
            return Response(
                content='{"error": "Rate limit exceeded. Please throttle analysis requests."}',
                status_code=429,
                media_type="application/json"
            )
        _request_counts[client_ip].append(now)

    response = await call_next(request)
    return response


class AnalyzeRequestPayload(BaseModel):
    target_id: str
    asset_id: str
    run_id: str = ""
    evidence: StructuredEvidence


class SignalsRequestPayload(BaseModel):
    target_id: str
    asset_id: str
    evidence: StructuredEvidence


@app.get("/health")
async def health_check():
    """Health check endpoint providing engine configuration telemetry."""
    return {
        "status": "ok",
        "service": "nexushunter-ai-analysis",
        "provider": config.provider,
        "model": config.model,
        "rate_limit_rpm": config.rate_limit_rpm,
        "base_url": config.base_url
    }


@app.post("/api/v1/analyze", response_model=AnalysisResult)
async def run_analysis(payload: AnalyzeRequestPayload):
    """Analyzes evidence through deterministic detectors and AI reasoning to produce candidates."""
    try:
        result = await analyzer.analyze(
            target_id=payload.target_id,
            asset_id=payload.asset_id,
            raw_evidence=payload.evidence,
            run_id=payload.run_id or None
        )
        return result
    except Exception as e:
        logger.error(f"Error during analysis run: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")


@app.post("/api/v1/signals")
async def extract_signals_only(payload: SignalsRequestPayload):
    """Executes purely deterministic detectors on evidence without invoking LLM."""
    signals = []
    for detector in analyzer.detectors:
        try:
            det_signals = detector.detect(payload.target_id, payload.asset_id, payload.evidence)
            signals.extend(det_signals)
        except Exception as e:
            logger.error(f"Detector {detector.detector_id} failed: {e}")

    return {
        "target_id": payload.target_id,
        "asset_id": payload.asset_id,
        "signals": [s.model_dump() for s in signals],
        "count": len(signals)
    }
