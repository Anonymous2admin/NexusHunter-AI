"""Base class and registry for deterministic security signal detectors."""

from abc import ABC, abstractmethod
from typing import List
from ..models import SecuritySignal
from ..schemas import StructuredEvidence


class BaseDetector(ABC):
    """Abstract base detector operating deterministically on observed evidence."""

    @property
    @abstractmethod
    def detector_id(self) -> str:
        """Unique detector identifier."""
        pass

    @abstractmethod
    def detect(self, target_id: str, asset_id: str, evidence: StructuredEvidence) -> List[SecuritySignal]:
        """Analyzes normalized evidence and emits zero or more preliminary signals.
        Must NEVER emit confirmed vulnerabilities.
        """
        pass
