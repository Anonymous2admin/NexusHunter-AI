"""Deterministic detector for passive information exposure and exposed debug/admin indicators."""

import re
from typing import List
from urllib.parse import urlparse
from .base import BaseDetector
from ..models import SecuritySignal, SeverityHint
from ..schemas import StructuredEvidence

SENSITIVE_PATH_PATTERNS = [
    (re.compile(r"/\.env(?:\.local|\.dev|\.prod)?$", re.IGNORECASE), "Environment Configuration File Exposure"),
    (re.compile(r"/\.git/(?:HEAD|config|index)", re.IGNORECASE), "Git Repository Exposure"),
    (re.compile(r"/actuator(?:/health|/env|/beans|/info)?$", re.IGNORECASE), "Spring Boot Actuator Endpoint Exposure"),
    (re.compile(r"/(?:swagger-ui|api-docs|v2/api-docs|v3/api-docs|openapi\.json)", re.IGNORECASE), "API Specification / Swagger Exposure"),
    (re.compile(r"/phpinfo\.php$", re.IGNORECASE), "PHP Info Diagnostic Exposure"),
    (re.compile(r"/(?:server-status|server-info)$", re.IGNORECASE), "Web Server Status Exposure"),
    (re.compile(r"/(?:debug|metrics|trace|profiler)(?:/.*)?$", re.IGNORECASE), "Diagnostic / Metrics Telemetry Exposure"),
]

PRIVATE_IP_PATTERN = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")


class InfoDisclosureDetector(BaseDetector):
    """Detects information disclosure indicators and exposed administrative routes passively."""

    @property
    def detector_id(self) -> str:
        return "deterministic.info_disclosure"

    def detect(self, target_id: str, asset_id: str, evidence: StructuredEvidence) -> List[SecuritySignal]:
        signals: List[SecuritySignal] = []

        # 1. Check paths from URLs and PageAssets
        all_urls = []
        if evidence.service:
            all_urls.append(evidence.service.url)
        all_urls.extend([u.url for u in evidence.urls])
        if hasattr(evidence, "page_assets") and evidence.page_assets:
            all_urls.extend([getattr(pa, "url", str(pa)) for pa in evidence.page_assets])

        seen_exposures = set()

        for url_str in all_urls:
            try:
                parsed = urlparse(url_str)
                for pattern, desc in SENSITIVE_PATH_PATTERNS:
                    if pattern.search(parsed.path):
                        if parsed.path not in seen_exposures:
                            seen_exposures.add(parsed.path)
                            signals.append(SecuritySignal(
                                signal_id=f"sig-info-path-{asset_id}-{len(signals)+1}",
                                signal_type="POTENTIAL_INFORMATION_EXPOSURE",
                                severity_hint=SeverityHint.MEDIUM,
                                evidence=f"Sensitive diagnostic route observed in crawl/page assets: '{parsed.path}' ({desc}) at {url_str}",
                                source="deterministic_detector",
                                asset_id=asset_id,
                                target_id=target_id,
                                url=url_str,
                                details={
                                    "endpoint": parsed.path,
                                    "exposure_type": desc,
                                    "recommended_validation": "Ensure diagnostic endpoint is bound to internal network interfaces or behind strict authentication."
                                }
                            ))
            except Exception:
                continue

        # 2. Check service headers and body for private IP disclosure
        if evidence.service:
            body = evidence.service.body_snippet or ""
            headers_str = " ".join(f"{k}: {v}" for k, v in evidence.service.headers.items())

            ip_match = PRIVATE_IP_PATTERN.search(headers_str) or PRIVATE_IP_PATTERN.search(body)
            if ip_match:
                signals.append(SecuritySignal(
                    signal_id=f"sig-info-ip-{asset_id}",
                    signal_type="POTENTIAL_INFORMATION_EXPOSURE",
                    severity_hint=SeverityHint.LOW,
                    evidence=f"Internal RFC 1918 private IPv4 address '{ip_match.group(0)}' exposed in passive HTTP response/headers at {evidence.service.url}",
                    source="deterministic_detector",
                    asset_id=asset_id,
                    target_id=target_id,
                    url=evidence.service.url,
                    details={"exposed_ip": ip_match.group(0)}
                ))

            # 3. Check for specific detailed server header banners
            server_header = evidence.service.headers.get("server", "")
            if re.search(r"/(?:\d+\.){1,3}\d+", server_header):
                signals.append(SecuritySignal(
                    signal_id=f"sig-info-banner-{asset_id}",
                    signal_type="POTENTIAL_INFORMATION_EXPOSURE",
                    severity_hint=SeverityHint.INFO,
                    evidence=f"Detailed server banner with granular version exposed in 'Server' header: '{server_header}'",
                    source="deterministic_detector",
                    asset_id=asset_id,
                    target_id=target_id,
                    url=evidence.service.url,
                    details={"server_banner": server_header}
                ))

        return signals
