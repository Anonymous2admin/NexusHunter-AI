"""Deterministic detector for race condition / concurrency-sensitive operation candidates."""

import re
from typing import List
from urllib.parse import urlparse
from .base import BaseDetector
from ..models import SecuritySignal, SeverityHint
from ..schemas import StructuredEvidence

CONCURRENCY_ENDPOINT_PATTERNS = [
    (re.compile(r"/(?:checkout|purchase|pay|payment|order/submit)", re.IGNORECASE), "Financial checkout / transaction processing", "Balance deduction / order completion race"),
    (re.compile(r"/(?:transfer|withdraw|deposit|fund)", re.IGNORECASE), "Asset / balance transfer operation", "Double-spend / concurrent withdrawal race"),
    (re.compile(r"/(?:coupon|discount|promo|voucher)/?(?:apply|redeem)?", re.IGNORECASE), "Coupon / promotional credit application", "Multi-redemption / limit bypass race"),
    (re.compile(r"/(?:claim|reward|airdrop|grant)", re.IGNORECASE), "One-time reward / entitlement claim", "Concurrent entitlement claim race"),
    (re.compile(r"/(?:vote|poll|survey/submit|like)", re.IGNORECASE), "Voting / tallying aggregation", "Concurrent vote counter race"),
    (re.compile(r"/(?:invite|register|signup|referral)", re.IGNORECASE), "Account registration / invite redemption", "Concurrent referral quota exhaustion race"),
    (re.compile(r"/(?:cart/items|cart/apply|inventory/reserve)", re.IGNORECASE), "Cart item allocation / inventory reservation", "Inventory overselling / reservation race"),
]


class ConcurrencyDetector(BaseDetector):
    """Flags state-transition operations and monetary endpoints without sending concurrent traffic."""

    @property
    def detector_id(self) -> str:
        return "deterministic.concurrency"

    def detect(self, target_id: str, asset_id: str, evidence: StructuredEvidence) -> List[SecuritySignal]:
        signals: List[SecuritySignal] = []
        all_urls = []
        if evidence.service:
            all_urls.append(evidence.service.url)
        all_urls.extend([u.url for u in evidence.urls])

        seen_routes = set()

        for url_str in all_urls:
            try:
                parsed = urlparse(url_str)
                path = parsed.path

                for pattern, op_desc, hypothesis in CONCURRENCY_ENDPOINT_PATTERNS:
                    if pattern.search(path):
                        if path not in seen_routes:
                            seen_routes.add(path)
                            signals.append(SecuritySignal(
                                signal_id=f"sig-concurrency-{asset_id}-{len(signals)+1}",
                                signal_type="POTENTIAL_CONCURRENCY_SENSITIVE_ENDPOINT",
                                severity_hint=SeverityHint.LOW,
                                evidence=f"Endpoint route '{path}' maps to concurrency-sensitive state operation: {op_desc} at {url_str}",
                                source="deterministic_detector",
                                asset_id=asset_id,
                                target_id=target_id,
                                url=url_str,
                                details={
                                    "endpoint": path,
                                    "operation_description": op_desc,
                                    "race_condition_hypothesis": hypothesis,
                                    "safe_validation_recommendation": "Inspect server-side concurrency safeguards: distributed locks, atomic database transactions (SELECT FOR UPDATE / serializable isolation), and strict idempotency key enforcement."
                                }
                            ))
                            break
            except Exception:
                continue

        return signals
