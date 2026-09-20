"""Pydantic schemas enforcing input validation, sanitization constraints, and LLM output parsing."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
from .models import CandidateState, FindingCandidate, FindingCategory, SecuritySignal


class ServiceEvidence(BaseModel):
    """Normalized HTTP service evidence."""
    url: str
    status_code: int = Field(ge=100, le=599)
    content_type: Optional[str] = None
    page_title: Optional[str] = None
    web_server: Optional[str] = None
    response_time_ms: Optional[int] = None
    tls_version: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    body_snippet: Optional[str] = None


class TechnologyEvidence(BaseModel):
    """Normalized technology observation evidence."""
    technology_name: str
    category: str
    version: Optional[str] = None
    confidence: str = "LOW"
    evidence: str = ""


class SecurityObservationEvidence(BaseModel):
    """Normalized passive security posture observation."""
    property_name: str
    is_present: bool
    details: Optional[str] = None
    raw_value: Optional[str] = None


class URLEvidence(BaseModel):
    """Discovered endpoint evidence."""
    url: str
    depth: Optional[int] = None
    source: Optional[str] = None


class StructuredEvidence(BaseModel):
    """Complete evidence bundle for an asset or service."""
    target_id: str
    asset_id: str
    job_id: Optional[str] = None
    service: Optional[ServiceEvidence] = None
    technologies: List[TechnologyEvidence] = Field(default_factory=list)
    security_observations: List[SecurityObservationEvidence] = Field(default_factory=list)
    urls: List[URLEvidence] = Field(default_factory=list)
    page_assets: List[Any] = Field(default_factory=list)
    response_metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("target_id", "asset_id")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()


class AnalyzeRequest(BaseModel):
    """API request payload for security analysis."""
    analysis_run_id: Optional[str] = None
    target_id: Optional[str] = None
    evidence: List[StructuredEvidence] = Field(default_factory=list, max_length=100)
    async_mode: bool = False


class AnalyzeResponse(BaseModel):
    """API response acknowledging or returning analysis results."""
    status: str  # "completed", "accepted", "failed"
    analysis_run_id: str
    candidates_count: int = 0
    signals_count: int = 0
    candidates: List[FindingCandidate] = Field(default_factory=list)
    signals: List[SecuritySignal] = Field(default_factory=list)
    cached: bool = False
    execution_time_ms: int = 0
    message: Optional[str] = None


class CandidateStateUpdateRequest(BaseModel):
    """State transition request for a candidate finding."""
    new_state: CandidateState
    reason: str = Field(min_length=3, max_length=500)


# --- Strict LLM Analysis Output Schema ---

class LLMAnalysisItem(BaseModel):
    """Individual candidate analysis from the LLM."""
    category: str = "OTHER"
    title: str = Field(min_length=3, max_length=200)
    confidence: float = 0.5
    confidence_score: Optional[float] = None
    candidate: bool = True
    reasoning_summary: Optional[str] = None
    reasoning: Optional[str] = None
    missing_evidence: Optional[str] = None
    required_validation: List[str] = Field(default_factory=list)
    validation_steps: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    recommended_verification: Optional[str] = None
    state: str = "ANALYSIS_CANDIDATE"

    def get_confidence(self) -> float:
        if self.confidence_score is not None:
            return max(0.0, min(1.0, self.confidence_score))
        return max(0.0, min(1.0, self.confidence))

    def get_reasoning(self) -> str:
        return self.reasoning or self.reasoning_summary or "Hypothesis derived from passive observations."

    def get_validation_steps(self) -> List[str]:
        if self.validation_steps:
            return self.validation_steps
        if self.required_validation:
            return self.required_validation
        return ["Verify service authorization and input controls in controlled test environment."]


class LLMAnalysisOutput(BaseModel):
    """Enforced structured JSON response contract for AI model."""
    analysis: List[LLMAnalysisItem] = Field(default_factory=list)
    candidates: List[LLMAnalysisItem] = Field(default_factory=list)
    summary: Optional[str] = None
    confidence_notes: Optional[str] = None
    metadata_notes: Optional[str] = None

    def get_items(self) -> List[LLMAnalysisItem]:
        if self.candidates:
            return self.candidates
        return self.analysis
