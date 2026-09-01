# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - Models Package
Exposes all canonical entities for strong typing across audit, threat operations, and defense engines.
"""

from domain.models.base import AISPRBaseModel, utc_now
from domain.models.evidence import Evidence, EvidenceReference, EvidenceCollectionResult
from domain.models.asset import AIAsset
from domain.models.attack import AttackTechnique
from domain.models.framework import FrameworkMapping
from domain.models.control import Control, ControlLink, ControlResult
from domain.models.remediation import Remediation
from domain.models.risk import Risk
from domain.models.finding import SecurityFinding, Finding
from domain.models.event import SecurityEvent
from domain.models.assessment import Assessment, AssessmentRun
from domain.models.contract import (
    RegulatoryMapping,
    TestDefinition,
    EvidenceRequirement,
    SecurityControlContract,
)

__all__ = [
    "AISPRBaseModel",
    "utc_now",
    "Evidence",
    "EvidenceReference",
    "EvidenceCollectionResult",
    "AIAsset",
    "AttackTechnique",
    "FrameworkMapping",
    "Control",
    "ControlLink",
    "ControlResult",
    "Remediation",
    "Risk",
    "SecurityFinding",
    "Finding",
    "SecurityEvent",
    "Assessment",
    "AssessmentRun",
    "RegulatoryMapping",
    "TestDefinition",
    "EvidenceRequirement",
    "SecurityControlContract",
]
