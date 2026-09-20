"""Registry of deterministic security signal detectors."""

from typing import List
from .base import BaseDetector
from .reflection import ReflectionDetector
from .idor_auth import IDORAuthDetector
from .ssrf import SSRFDetector
from .injection import InjectionAnomalyDetector
from .concurrency import ConcurrencyDetector
from .info_disclosure import InfoDisclosureDetector

ALL_DETECTORS: List[BaseDetector] = [
    ReflectionDetector(),
    IDORAuthDetector(),
    SSRFDetector(),
    InjectionAnomalyDetector(),
    ConcurrencyDetector(),
    InfoDisclosureDetector(),
]

__all__ = [
    "BaseDetector",
    "ReflectionDetector",
    "IDORAuthDetector",
    "SSRFDetector",
    "InjectionAnomalyDetector",
    "ConcurrencyDetector",
    "InfoDisclosureDetector",
    "ALL_DETECTORS",
]
