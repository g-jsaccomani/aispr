# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model Package
Top-level entrypoint for domain entities and enumerations.
"""

from domain.enums import (
    CloudProvider,
    FindingSeverity,
    FindingStatus,
    FindingSource,
    EvidenceType,
    EvidenceStatus,
    ExecutionMode,
    ConfidenceLevel,
    AssetType,
    ControlEvaluation,
    ControlRelationType,
    RiskLevel,
    AssessmentStatus,
    AssessmentType,
    AutomationLevel,
    MappingConfidence,
    FrameworkName,
)

from domain.models import (
    AISPRBaseModel,
    utc_now,
    Evidence,
    EvidenceReference,
    EvidenceCollectionResult,
    AIAsset,
    AttackTechnique,
    FrameworkMapping,
    Control,
    ControlLink,
    ControlResult,
    Remediation,
    Risk,
    SecurityFinding,
    Finding,
    SecurityEvent,
    Assessment,
    AssessmentRun,
    RegulatoryMapping,
    TestDefinition,
    EvidenceRequirement,
    SecurityControlContract,
)

from domain.sanitization import (
    redact_string,
    sanitize_value,
    sanitize_evidence_content,
)

__all__ = [
    # Enums
    "CloudProvider",
    "FindingSeverity",
    "FindingStatus",
    "FindingSource",
    "EvidenceType",
    "EvidenceStatus",
    "ExecutionMode",
    "ConfidenceLevel",
    "AssetType",
    "ControlEvaluation",
    "ControlRelationType",
    "RiskLevel",
    "AssessmentStatus",
    "AssessmentType",
    "AutomationLevel",
    "MappingConfidence",
    "FrameworkName",
    # Models
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
    # Sanitization
    "redact_string",
    "sanitize_value",
    "sanitize_evidence_content",
]
