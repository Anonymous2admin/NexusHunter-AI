"""Deterministic detector for potential server-side request / URL dispatch parameters."""

from typing import List
from urllib.parse import parse_qs, urlparse
from .base import BaseDetector
from ..models import SecuritySignal, SeverityHint
from ..schemas import StructuredEvidence

SSRF_PARAM_NAMES = {
    "url", "redirect", "callback", "next", "destination", "webhook",
    "target", "endpoint", "uri", "feed", "proxy", "host", "domain",
    "fetch", "file_url", "image_url", "doc_url", "import_url"
}

SSRF_PATH_KEYWORDS = {
    "webhook", "import", "fetch", "proxy", "render", "preview", "download"
}


class SSRFDetector(BaseDetector):
    """Flags parameters and routes that accept remote URL destinations without performing active requests."""

    @property
    def detector_id(self) -> str:
        return "deterministic.ssrf"

    def detect(self, target_id: str, asset_id: str, evidence: StructuredEvidence) -> List[SecuritySignal]:
        signals: List[SecuritySignal] = []
        all_urls = []
        if evidence.service:
            all_urls.append(evidence.service.url)
        all_urls.extend([u.url for u in evidence.urls])

        seen_params = set()

        for url_str in all_urls:
            try:
                parsed = urlparse(url_str)
                params = parse_qs(parsed.query)

                for qname, qvals in params.items():
                    lower_qname = qname.lower()
                    if lower_qname in SSRF_PARAM_NAMES:
                        key = f"{parsed.path}:{lower_qname}"
                        if key not in seen_params:
                            seen_params.add(key)
                            signals.append(SecuritySignal(
                                signal_id=f"sig-ssrf-param-{asset_id}-{len(signals)+1}",
                                signal_type="POTENTIAL_SERVER_SIDE_REQUEST",
                                severity_hint=SeverityHint.MEDIUM,
                                evidence=f"Query parameter '{qname}' at '{parsed.path}' accepts URL-like destination input (observed sample: '{qvals[0][:40] if qvals else ''}')",
                                source="deterministic_detector",
                                asset_id=asset_id,
                                target_id=target_id,
                                url=url_str,
                                details={
                                    "parameter": qname,
                                    "endpoint": parsed.path,
                                    "sensitivity_rationale": "Parameter name indicates remote URL retrieval, forwarding, or callback dispatch.",
                                    "safe_verification_recommendation": "Verify fail-closed outbound allowlist, disallow private/loopback/link-local IPv4/IPv6, and prevent cloud metadata access."
                                }
                            ))

                # Check path keywords
                for kw in SSRF_PATH_KEYWORDS:
                    if kw in parsed.path.lower():
                        key = f"path:{parsed.path}:{kw}"
                        if key not in seen_params:
                            seen_params.add(key)
                            signals.append(SecuritySignal(
                                signal_id=f"sig-ssrf-path-{asset_id}-{len(signals)+1}",
                                signal_type="POTENTIAL_SERVER_SIDE_REQUEST",
                                severity_hint=SeverityHint.LOW,
                                evidence=f"Endpoint route '{parsed.path}' matches remote resource ingestion keyword '{kw}' at {url_str}",
                                source="deterministic_detector",
                                asset_id=asset_id,
                                target_id=target_id,
                                url=url_str,
                                details={
                                    "endpoint": parsed.path,
                                    "keyword": kw,
                                    "sensitivity_rationale": "Route is commonly associated with external asset ingestion or webhook delivery.",
                                    "safe_verification_recommendation": "Confirm server-side egress egress controls and URL parser validation."
                                }
                            ))
                            break
            except Exception:
                continue

        return signals
