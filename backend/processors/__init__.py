"""Processor modules for the CTI platform."""

# Explicit exports for easier importing
from backend.processors.deduplicator import Deduplicator
from backend.processors.normalizer import IOCNormalizer
from backend.processors.risk_engine import RiskEngine

__all__ = [
    "Deduplicator",
    "IOCNormalizer",
    "RiskEngine"
]       
