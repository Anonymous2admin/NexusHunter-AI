"""Mock AI provider for testing and deterministic offline analysis."""

import json
from typing import Optional
from .base import BaseAIProvider


class MockAIProvider(BaseAIProvider):
    """Generates structured, schema-compliant responses without external API calls."""

    async def analyze(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        # Return a structured JSON adhering to LLMAnalysisOutput schema
        response_payload = {
            "summary": "Mock analysis completed based on verified evidence items and deterministic signals.",
            "confidence_notes": "All hypotheses are flagged as CANDIDATE stage requiring controlled validation.",
            "candidates": []
        }

        # Check for keywords in prompt to generate realistic structured candidates
        if "REFLECTION_INDICATOR" in user_prompt:
            response_payload["candidates"].append({
                "title": "Potential Reflected Input on Query Parameter",
                "category": "XSS",
                "confidence_score": 0.65,
                "reasoning": "Observed reflection of user input parameter in response body without encoding verification.",
                "evidence_references": ["Query parameter reflection observed"],
                "missing_evidence": "Verification of context escaping and Content-Security-Policy script restrictions.",
                "validation_steps": [
                    "Perform passive header analysis for CSP directives.",
                    "Verify if output encoding is applied to user-controlled parameters."
                ],
                "recommended_verification": "Controlled non-destructive verification with harmless canary strings.",
                "state": "ANALYSIS_CANDIDATE"
            })

        if "OBJECT_IDENTIFIER_DETECTED" in user_prompt or "POTENTIAL_AUTHORIZATION_ISSUE" in user_prompt:
            response_payload["candidates"].append({
                "title": "Potential Insecure Direct Object Reference (IDOR)",
                "category": "IDOR",
                "confidence_score": 0.55,
                "reasoning": "Endpoint path/query exposes sequential integer or UUID object reference pattern.",
                "evidence_references": ["Discrete resource identifier observed in endpoint"],
                "missing_evidence": "Proof of cross-account access control failure; only identifier presence is confirmed.",
                "validation_steps": [
                    "Compare response codes across authorized session boundaries.",
                    "Verify tenancy scoping at API gateway or data layer."
                ],
                "recommended_verification": "Perform dual-session comparative request validation without privilege modification.",
                "state": "ANALYSIS_CANDIDATE"
            })

        if "POTENTIAL_SERVER_SIDE_REQUEST" in user_prompt:
            response_payload["candidates"].append({
                "title": "Potential Server-Side Request Destination Parameter",
                "category": "SSRF",
                "confidence_score": 0.60,
                "reasoning": "Parameter accepts external URL string destinations requiring outbound dispatch validation.",
                "evidence_references": ["URL destination parameter detected in query string"],
                "missing_evidence": "Confirmation whether remote fetch is executed and whether egress filtering blocks private subnets.",
                "validation_steps": [
                    "Check network egress policy and private CIDR block filtering.",
                    "Validate parser enforcement of allowable schemes (https only)."
                ],
                "recommended_verification": "Test against internal non-routable dummy domain or dedicated loopback validation mock.",
                "state": "ANALYSIS_CANDIDATE"
            })

        if "POTENTIAL_INPUT_HANDLING_ANOMALY" in user_prompt:
            response_payload["candidates"].append({
                "title": "Database Syntax Error in Passive Response",
                "category": "INJECTION",
                "confidence_score": 0.70,
                "reasoning": "Observed database exception or syntax error signature in passive response body.",
                "evidence_references": ["Database exception pattern identified in response snippet"],
                "missing_evidence": "Confirmation of arbitrary syntax interpolation beyond passive error display.",
                "validation_steps": [
                    "Inspect ORM / query building source code for parameterization.",
                    "Verify custom error pages to prevent diagnostic disclosure."
                ],
                "recommended_verification": "Code review of backend query formation and error handling middlewares.",
                "state": "ANALYSIS_CANDIDATE"
            })

        return json.dumps(response_payload)
