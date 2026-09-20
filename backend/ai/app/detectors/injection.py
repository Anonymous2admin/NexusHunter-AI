"""Deterministic detector for passive input handling anomalies and syntax/database errors."""

import re
from typing import List
from .base import BaseDetector
from ..models import SecuritySignal, SeverityHint
from ..schemas import StructuredEvidence

# Signatures for database, ORM, and parser errors in observed response snippets
ERROR_SIGNATURES = [
    (re.compile(r"SQL (?:syntax|statement) (?:error|exception)", re.IGNORECASE), "SQL Syntax Error", "generic_sql"),
    (re.compile(r"syntax error at or near\b", re.IGNORECASE), "PostgreSQL Syntax Error", "postgresql"),
    (re.compile(r"ORA-\d{5}", re.IGNORECASE), "Oracle Error Code", "oracle"),
    (re.compile(r"ODBC (?:SQL Server|Driver) Driver", re.IGNORECASE), "ODBC Driver Error", "mssql"),
    (re.compile(r"sqlite3\.OperationalError", re.IGNORECASE), "SQLite Operational Error", "sqlite"),
    (re.compile(r"org\.hibernate\.exception", re.IGNORECASE), "Hibernate ORM Exception", "hibernate"),
    (re.compile(r"django\.db\.utils\.ProgrammingError", re.IGNORECASE), "Django Database ProgrammingError", "django"),
    (re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE), "Python Traceback Exception", "python"),
    (re.compile(r"NullPointerException|ClassNotFoundException", re.IGNORECASE), "Java Runtime Exception", "java"),
    (re.compile(r"Fatal error:.*?in\s+/[^\s]+\.php", re.IGNORECASE), "PHP Fatal Runtime Error", "php"),
    (re.compile(r"TypeError:\s+Cannot read propert", re.IGNORECASE), "Node.js / V8 Type Error", "nodejs"),
]


class InjectionAnomalyDetector(BaseDetector):
    """Detects database, parser, and runtime error signatures without active payload injection."""

    @property
    def detector_id(self) -> str:
        return "deterministic.injection"

    def detect(self, target_id: str, asset_id: str, evidence: StructuredEvidence) -> List[SecuritySignal]:
        signals: List[SecuritySignal] = []
        if not evidence.service or not evidence.service.body_snippet:
            return signals

        body = evidence.service.body_snippet
        url = evidence.service.url or ""

        for pattern, sig_name, tech_hint in ERROR_SIGNATURES:
            match = pattern.search(body)
            if match:
                matched_snippet = body[max(0, match.start()-40):min(len(body), match.end()+60)].strip()
                signals.append(SecuritySignal(
                    signal_id=f"sig-anomaly-{asset_id}-{tech_hint}",
                    signal_type="POTENTIAL_INPUT_HANDLING_ANOMALY",
                    severity_hint=SeverityHint.MEDIUM,
                    evidence=f"Passive response contains database/parser exception signature '{sig_name}': {matched_snippet}",
                    source="deterministic_detector",
                    asset_id=asset_id,
                    target_id=target_id,
                    url=url,
                    details={
                        "signature_name": sig_name,
                        "technology_hint": tech_hint,
                        "matched_snippet": matched_snippet[:120],
                        "recommended_validation": "Review parameterized query implementations, ORM configuration, and production error-handling disclosure controls."
                    }
                ))

        return signals
