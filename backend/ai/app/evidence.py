"""Evidence collection, normalization, secret redaction, and sanitization layer."""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from .models import FindingEvidenceItem
from .schemas import StructuredEvidence


# Common secret / token query parameters to redact
SENSITIVE_PARAM_NAMES = {
    "token", "access_token", "auth", "api_key", "apikey", "key", "secret",
    "password", "passwd", "pwd", "session", "session_id", "sessionid",
    "jwt", "bearer", "signature", "sig", "private_key", "client_secret"
}

# Sensitive HTTP headers to completely redact
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-access-token", "api-key", "token"
}

# Regex patterns for accidental credential/key leakage
BEARER_PATTERN = re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+")
API_KEY_PATTERN = re.compile(r"(api[_-]?key|secret|token)[\s:=]+['\"]?([A-Za-z0-9\-_]{16,})['\"]?", re.IGNORECASE)


class EvidenceSanitizer:
    """Strictly redacts sensitive authorization, credentials, and secrets before AI processing."""

    @classmethod
    def sanitize_url(cls, url_str: str) -> str:
        """Strips credentials and masks sensitive query parameters from a URL."""
        if not url_str:
            return ""
        try:
            parsed = urlparse(url_str)
            # Remove username:password if present in netloc
            netloc = parsed.netloc
            if "@" in netloc:
                netloc = netloc.split("@", 1)[1]

            # Redact sensitive query parameters
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            redacted_params = {}
            for k, vals in query_params.items():
                if k.lower() in SENSITIVE_PARAM_NAMES:
                    redacted_params[k] = ["[REDACTED]"]
                else:
                    redacted_params[k] = vals

            sanitized_query = urlencode(redacted_params, doseq=True)
            return urlunparse((
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                sanitized_query,
                parsed.fragment
            ))
        except Exception:
            return "[INVALID_URL]"

    @classmethod
    def sanitize_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        """Removes all authorization and session headers."""
        sanitized = {}
        for k, v in headers.items():
            lower_k = k.lower()
            if lower_k in SENSITIVE_HEADERS:
                sanitized[k] = "[REDACTED]"
            else:
                # Mask any inline bearer or jwt token in standard headers
                val = BEARER_PATTERN.sub(r"\1[REDACTED]", v)
                val = JWT_PATTERN.sub("[REDACTED_JWT]", val)
                sanitized[k] = val
        return sanitized

    @classmethod
    def sanitize_text(cls, text: Optional[str], max_len: int = 4096) -> str:
        """Redacts inline credentials and truncates to safe length."""
        if not text:
            return ""
        # Redact JWTs and bearer tokens
        clean = BEARER_PATTERN.sub(r"\1[REDACTED]", text)
        clean = JWT_PATTERN.sub("[REDACTED_JWT]", clean)
        clean = API_KEY_PATTERN.sub(r"\1=[REDACTED]", clean)
        if len(clean) > max_len:
            clean = clean[:max_len] + f"\n...[TRUNCATED: original length {len(text)} bytes]"
        return clean

    @classmethod
    def sanitize_evidence(cls, evidence: StructuredEvidence, max_text_len: int = 4096) -> StructuredEvidence:
        """Deeply sanitizes an entire StructuredEvidence object."""
        sanitized_service = None
        if evidence.service:
            sanitized_service = evidence.service.model_copy(update={
                "url": cls.sanitize_url(evidence.service.url),
                "headers": cls.sanitize_headers(evidence.service.headers),
                "body_snippet": cls.sanitize_text(evidence.service.body_snippet, max_text_len),
                "page_title": cls.sanitize_text(evidence.service.page_title, 256),
            })

        sanitized_urls = [
            u.model_copy(update={"url": cls.sanitize_url(u.url)})
            for u in evidence.urls
        ]

        return evidence.model_copy(update={
            "service": sanitized_service,
            "urls": sanitized_urls,
        })


class EvidenceCollector:
    """Extracts, hashes, and compiles evidence items for candidate verification."""

    @staticmethod
    def compute_evidence_hash(target_id: str, evidence: StructuredEvidence) -> str:
        """Calculates a deterministic SHA-256 digest of sanitized evidence for caching."""
        components = [
            f"target:{target_id}",
            f"asset:{evidence.asset_id}",
        ]
        if evidence.service:
            components.append(f"url:{evidence.service.url}")
            components.append(f"status:{evidence.service.status_code}")
            components.append(f"server:{evidence.service.web_server or ''}")
        for t in sorted(evidence.technologies, key=lambda x: x.technology_name):
            components.append(f"tech:{t.technology_name}:{t.version or ''}")
        for u in sorted(evidence.urls, key=lambda x: x.url):
            components.append(f"ep:{u.url}")

        raw = "|".join(components)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def build_evidence_items(
        target_id: str,
        asset_id: str,
        evidence: StructuredEvidence
    ) -> List[FindingEvidenceItem]:
        """Extracts discrete verifiable evidence items."""
        items: List[FindingEvidenceItem] = []
        idx = 1

        if evidence.service:
            items.append(FindingEvidenceItem(
                id=f"evi-{asset_id}-svc-{idx}",
                evidence_type="HTTP_SERVICE",
                reference_id=evidence.service.url,
                summary=f"HTTP {evidence.service.status_code} ({evidence.service.content_type or 'unknown'}) at {evidence.service.url}",
                description=f"HTTP {evidence.service.status_code} ({evidence.service.content_type or 'unknown'}) at {evidence.service.url}",
                details={
                    "status_code": evidence.service.status_code,
                    "server": evidence.service.web_server,
                    "response_time_ms": evidence.service.response_time_ms,
                }
            ))
            idx += 1

            for header_name, header_val in evidence.service.headers.items():
                if header_name.lower() in ("server", "x-powered-by", "access-control-allow-origin", "strict-transport-security", "content-security-policy"):
                    items.append(FindingEvidenceItem(
                        id=f"evi-{asset_id}-hdr-{idx}",
                        evidence_type="HTTP_RESPONSE_HEADER",
                        reference_id=f"{evidence.service.url}:{header_name}",
                        summary=f"Header {header_name}: {header_val}",
                        description=f"Header {header_name}: {header_val}",
                        details={"header": header_name, "value": header_val}
                    ))
                    idx += 1

        for tech in evidence.technologies:
            items.append(FindingEvidenceItem(
                id=f"evi-{asset_id}-tech-{idx}",
                evidence_type="TECHNOLOGY_FINGERPRINT",
                reference_id=tech.technology_name,
                summary=f"Detected {tech.technology_name} ({tech.category}) v={tech.version or 'unknown'} via {tech.evidence}",
                description=f"Detected {tech.technology_name} ({tech.category}) v={tech.version or 'unknown'} via {tech.evidence}",
                details={"category": tech.category, "confidence": tech.confidence}
            ))
            idx += 1

        for obs in evidence.security_observations:
            items.append(FindingEvidenceItem(
                id=f"evi-{asset_id}-sec-{idx}",
                evidence_type="SECURITY_OBSERVATION",
                reference_id=obs.property_name,
                summary=f"Property {obs.property_name}: present={obs.is_present} ({obs.details or ''})",
                description=f"Property {obs.property_name}: present={obs.is_present} ({obs.details or ''})",
                details={"present": obs.is_present, "raw_value": obs.raw_value}
            ))
            idx += 1

        for item in items:
            raw = f"{item.evidence_type}:{item.reference_id}:{item.summary}"
            item.sha256 = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        return items

    def collect(self, evidence: StructuredEvidence) -> List[FindingEvidenceItem]:
        """Convenience method collecting evidence items with sha256 checksums."""
        return self.build_evidence_items(evidence.target_id, evidence.asset_id, evidence)
