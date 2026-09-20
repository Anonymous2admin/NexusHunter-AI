"""Deterministic detector for potential authorization and object identifier issues."""

import re
from typing import List
from urllib.parse import parse_qs, urlparse
from .base import BaseDetector
from ..models import SecuritySignal, SeverityHint
from ..schemas import StructuredEvidence

# Regex patterns for resource identifiers in URI paths
UUID_PATTERN = re.compile(r"/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", re.IGNORECASE)
INT_ID_PATTERN = re.compile(r"/(?:users|accounts|orders|invoices|documents|items|profiles|teams|tenants|files)/(\d+)", re.IGNORECASE)
ID_QUERY_PARAM_NAMES = {"id", "user_id", "userid", "account_id", "accountid", "doc_id", "order_id", "profile_id"}


class IDORAuthDetector(BaseDetector):
    """Identifies resource identifiers and authorization differences without active probing."""

    @property
    def detector_id(self) -> str:
        return "deterministic.idor_auth"

    def detect(self, target_id: str, asset_id: str, evidence: StructuredEvidence) -> List[SecuritySignal]:
        signals: List[SecuritySignal] = []
        all_urls = []
        if evidence.service:
            all_urls.append(evidence.service.url)
        all_urls.extend([u.url for u in evidence.urls])

        seen_patterns = set()

        for url_str in all_urls:
            try:
                parsed = urlparse(url_str)
                path = parsed.path

                # Check path for integer identifiers under sensitive resource prefixes
                int_match = INT_ID_PATTERN.search(path)
                if int_match:
                    match_str = int_match.group(0)
                    if match_str not in seen_patterns:
                        seen_patterns.add(match_str)
                        signals.append(SecuritySignal(
                            signal_id=f"sig-auth-path-{asset_id}-{len(signals)+1}",
                            signal_type="OBJECT_IDENTIFIER_DETECTED",
                            severity_hint=SeverityHint.LOW,
                            evidence=f"Endpoint path '{path}' contains discrete object resource identifier '{int_match.group(1)}' at {url_str}",
                            source="deterministic_detector",
                            asset_id=asset_id,
                            target_id=target_id,
                            url=url_str,
                            details={
                                "endpoint": path,
                                "identifier_location": "path",
                                "matched_segment": match_str,
                                "required_validation": "Controlled access control validation across distinct user context boundaries without privilege escalation."
                            }
                        ))

                # Check path for UUID identifiers
                uuid_match = UUID_PATTERN.search(path)
                if uuid_match:
                    match_str = uuid_match.group(0)
                    if match_str not in seen_patterns:
                        seen_patterns.add(match_str)
                        signals.append(SecuritySignal(
                            signal_id=f"sig-auth-uuid-{asset_id}-{len(signals)+1}",
                            signal_type="OBJECT_IDENTIFIER_DETECTED",
                            severity_hint=SeverityHint.INFO,
                            evidence=f"Endpoint path '{path}' contains UUID resource identifier at {url_str}",
                            source="deterministic_detector",
                            asset_id=asset_id,
                            target_id=target_id,
                            url=url_str,
                            details={
                                "endpoint": path,
                                "identifier_location": "path_uuid",
                                "required_validation": "Verify tenancy boundaries and object authorization controls."
                            }
                        ))

                # Check query parameters for object ID keys
                query_params = parse_qs(parsed.query)
                for qname, qvals in query_params.items():
                    if qname.lower() in ID_QUERY_PARAM_NAMES:
                        sig_key = f"{path}:{qname.lower()}"
                        if sig_key not in seen_patterns:
                            seen_patterns.add(sig_key)
                            signals.append(SecuritySignal(
                                signal_id=f"sig-auth-param-{asset_id}-{len(signals)+1}",
                                signal_type="OBJECT_IDENTIFIER_DETECTED",
                                severity_hint=SeverityHint.LOW,
                                evidence=f"Query parameter '{qname}' presents direct object reference pattern at {url_str}",
                                source="deterministic_detector",
                                asset_id=asset_id,
                                target_id=target_id,
                                url=url_str,
                                details={
                                    "endpoint": path,
                                    "identifier_location": f"query_parameter:{qname}",
                                    "required_validation": "Verify server enforces session authorization on referenced object."
                                }
                            ))

            except Exception:
                continue

        # Check for status code anomalies (e.g. 401 Unauthorized vs 403 Forbidden vs 200 with WWW-Authenticate header)
        if evidence.service:
            if evidence.service.status_code == 401 and "www-authenticate" in evidence.service.headers:
                signals.append(SecuritySignal(
                    signal_id=f"sig-auth-status-{asset_id}",
                    signal_type="INCONSISTENT_AUTH_STATUS",
                    severity_hint=SeverityHint.INFO,
                    evidence=f"Service returned 401 with WWW-Authenticate header: {evidence.service.headers.get('www-authenticate')}",
                    source="deterministic_detector",
                    asset_id=asset_id,
                    target_id=target_id,
                    url=evidence.service.url,
                    details={"status_code": 401, "auth_header": evidence.service.headers.get("www-authenticate")}
                ))

        return signals
