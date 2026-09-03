# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Findings Correlator - Package
Deterministic pipeline: Normalizer → Deduplicator → ControlMapper → SeverityEngine → EvidenceValidator → Correlator
"""

from audit.engine.correlator.normalizer import FindingNormalizer
from audit.engine.correlator.deduplicator import FindingDeduplicator
from audit.engine.correlator.control_mapper import ControlMapper
from audit.engine.correlator.severity_engine import SeverityEngine
from audit.engine.correlator.evidence_validator import EvidenceValidator
from audit.engine.correlator.correlator import DeterministicCorrelator

__all__ = [
    "FindingNormalizer",
    "FindingDeduplicator",
    "ControlMapper",
    "SeverityEngine",
    "EvidenceValidator",
    "DeterministicCorrelator",
]
