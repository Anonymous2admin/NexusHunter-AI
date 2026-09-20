"""Data models and enums representing finding candidates, evidence, and signals."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CandidateState(str, Enum):
    """Lifecycle states for security findings.
    CONFIRMED is deliberately prohibited until independent active verification occurs in later phases.
    """
    CANDIDATE = "CANDIDATE"
    ANALYSIS_CANDIDATE = "CANDIDATE"
    NEEDS_VALIDATION = "NEEDS_VALIDATION"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    DUPLICATE = "DUPLICATE"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"


class FindingCategory(str, Enum):
    """Categorization for potential security weaknesses."""
    POTENTIAL_AUTHORIZATION_ISSUE = "POTENTIAL_AUTHORIZATION_ISSUE"
    POTENTIAL_SERVER_SIDE_REQUEST = "POTENTIAL_SERVER_SIDE_REQUEST"
    POTENTIAL_INPUT_HANDLING_ANOMALY = "POTENTIAL_INPUT_HANDLING_ANOMALY"
    POTENTIAL_CONCURRENCY_SENSITIVE_ENDPOINT = "POTENTIAL_CONCURRENCY_SENSITIVE_ENDPOINT"
    POTENTIAL_INFORMATION_EXPOSURE = "POTENTIAL_INFORMATION_EXPOSURE"
    POTENTIAL_MISCONFIGURATION = "POTENTIAL_MISCONFIGURATION"
    XSS = "XSS"
    SQLI = "SQLI"
    IDOR = "IDOR"
    SSRF = "SSRF"
    RACE_CONDITION = "RACE_CONDITION"
    INJECTION = "INJECTION"
    INFO_DISCLOSURE = "INFO_DISCLOSURE"
    OTHER = "OTHER"


class SeverityHint(str, Enum):
    """Non-binding severity indicator for triage prioritization."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class SecuritySignal(BaseModel):
    """Deterministic or observational signal preceding AI analysis."""
    signal_id: str
    signal_type: str
    severity_hint: SeverityHint = SeverityHint.LOW
    evidence: str
    source: str = "deterministic_detector"
    asset_id: Optional[str] = None
    target_id: Optional[str] = None
    url: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FindingEvidenceItem(BaseModel):
    """Mandatory structured evidence reference anchoring a candidate."""
    id: str
    candidate_id: Optional[str] = None
    evidence_type: str  # e.g., "HTTP_RESPONSE_HEADER", "URL_PARAMETER", "PAGE_BODY_SNIPPET", "STATUS_CODE"
    reference_id: str   # e.g., asset ID, service ID, URL record ID
    summary: str = ""
    description: str = ""
    sha256: str = ""
    data: Dict[str, Any] = Field(default_factory=dict)
    details: Dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FindingCandidate(BaseModel):
    """Candidate security finding awaiting controlled active validation."""
    id: str
    target_id: str
    asset_id: str
    job_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    category: FindingCategory
    title: str
    description: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence_breakdown: Dict[str, float] = Field(default_factory=dict)
    state: CandidateState = CandidateState.CANDIDATE
    signals: List[SecuritySignal] = Field(default_factory=list)
    evidence: List[FindingEvidenceItem] = Field(default_factory=list)
    required_validation: List[str] = Field(default_factory=list)
    validation_steps: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    reasoning: str = ""
    reasoning_summary: str = ""
    missing_evidence: str = ""
    recommended_verification: str = ""
    is_mock: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def __init__(self, **data):
        # Support aliases
        if "candidate_id" in data and "id" not in data:
            data["id"] = data.pop("candidate_id")
        if "confidence_score" in data and "confidence" not in data:
            data["confidence"] = data.pop("confidence_score")
        if "run_id" in data and "analysis_run_id" not in data:
            data["analysis_run_id"] = data.pop("run_id")
        if "reasoning" in data and not data.get("reasoning_summary"):
            data["reasoning_summary"] = data["reasoning"]
        if "reasoning_summary" in data and not data.get("reasoning"):
            data["reasoning"] = data["reasoning_summary"]
        if "validation_steps" in data and not data.get("required_validation"):
            data["required_validation"] = data["validation_steps"]
        if "required_validation" in data and not data.get("validation_steps"):
            data["validation_steps"] = data["required_validation"]
        if "description" not in data or not data["description"]:
            data["description"] = data.get("reasoning", data.get("title", ""))
        super().__init__(**data)


class AnalysisResult(BaseModel):
    """Aggregate result from an analysis run."""
    run_id: str
    target_id: str
    asset_id: str
    signals: List[SecuritySignal] = Field(default_factory=list)
    candidates: List[FindingCandidate] = Field(default_factory=list)
    evidence_items: List[FindingEvidenceItem] = Field(default_factory=list)
    summary: str = ""
    confidence_notes: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AnalysisRunStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AnalysisRun(BaseModel):
    """Execution record for an evidence analysis batch."""
    id: str
    target_id: str
    asset_id: Optional[str] = None
    status: AnalysisRunStatus = AnalysisRunStatus.PENDING
    candidates_count: int = 0
    signals_count: int = 0
    error: Optional[str] = None
    provider_used: str = "mock"
    execution_time_ms: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
