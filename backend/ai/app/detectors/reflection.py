"""Deterministic detector for reflected input indicators."""

import re
from typing import List
from urllib.parse import parse_qs, urlparse
from .base import BaseDetector
from ..models import SecuritySignal, SeverityHint
from ..schemas import StructuredEvidence


class ReflectionDetector(BaseDetector):
    """Detects reflected parameters and input echo indicators in HTTP responses."""

    @property
    def detector_id(self) -> str:
        return "deterministic.reflection"

    def detect(self, target_id: str, asset_id: str, evidence: StructuredEvidence) -> List[SecuritySignal]:
        signals: List[SecuritySignal] = []
        if not evidence.service:
            return signals

        body = evidence.service.body_snippet or ""
        service_url = evidence.service.url or ""

        # Collect all query parameter keys/values from service URL and discovered URLs
        all_urls = [service_url] + [u.url for u in evidence.urls]
        for url_str in all_urls:
            try:
                parsed = urlparse(url_str)
                params = parse_qs(parsed.query)
                for param_name, param_vals in params.items():
                    for val in param_vals:
                        if len(val) >= 3 and val in body:
                            signals.append(SecuritySignal(
                                signal_id=f"sig-refl-{asset_id}-{param_name}",
                                signal_type="REFLECTION_INDICATOR",
                                severity_hint=SeverityHint.LOW,
                                evidence=f"Query parameter '{param_name}' value '{val}' observed verbatim in HTTP response body at {url_str}",
                                source="deterministic_detector",
                                asset_id=asset_id,
                                target_id=target_id,
                                url=url_str,
                                details={
                                    "parameter": param_name,
                                    "reflected_value": val[:64],
                                    "context": "response_body",
                                }
                            ))
            except Exception:
                continue

        # Look for typical reflection placeholder indicators
        if re.search(r"<[^>]*\b(on\w+|src|href)\s*=\s*['\"][^'\"]*\{[^\}]+\}['\"]", body, re.IGNORECASE):
            signals.append(SecuritySignal(
                signal_id=f"sig-tmpl-{asset_id}",
                signal_type="REFLECTION_INDICATOR",
                severity_hint=SeverityHint.LOW,
                evidence=f"Template expression or dynamic placeholder pattern detected in response body at {service_url}",
                source="deterministic_detector",
                asset_id=asset_id,
                target_id=target_id,
                url=service_url,
                details={"context": "template_expression"}
            ))

        return signals
