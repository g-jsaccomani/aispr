# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - Risk Entity
"""

import uuid
from datetime import datetime
from typing import List, Optional, Any, Dict
from pydantic import Field, field_validator

from domain.enums import RiskLevel, FindingSeverity, PostureTier
from domain.models.base import AISPRBaseModel, utc_now


class Risk(AISPRBaseModel):
    """
    Evaluated threat or vulnerability risk profiling blast radius and exploitability.
    """
    risk_id: str = Field(default_factory=lambda: f"RSK-{uuid.uuid4().hex[:8].upper()}")
    title: str
    level: RiskLevel = Field(default=RiskLevel.MEDIUM)
    impact: str = ""
    likelihood: str = ""
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_assets: List[str] = Field(default_factory=list)
    description: Optional[str] = None

    @field_validator("level", mode="before")
    @classmethod
    def parse_risk_level(cls, v: Any) -> RiskLevel:
        if isinstance(v, str):
            try:
                return RiskLevel(v.upper())
            except ValueError:
                raise ValueError(f"Invalid RiskLevel: '{v}'")
        return v


class RiskTraceEntry(AISPRBaseModel):
    """
    Machine-readable calculation trace entry recording rule evaluations,
    inputs, normalizations, and intermediate results.
    """
    rule_id: str
    input_value: Any
    normalized_value: Any
    calculation_result: Any
    description: Optional[str] = None


class FindingRiskAssessment(AISPRBaseModel):
    """
    Deterministic risk profiling for a specific canonical finding.
    """
    finding_id: str
    title: str
    severity: FindingSeverity
    base_severity_score: float
    exploitability_multiplier: float = 1.0
    exposure_multiplier: float = 1.0
    asset_criticality_multiplier: float = 1.0
    data_sensitivity_multiplier: float = 1.0
    privilege_multiplier: float = 1.0
    attack_path_multiplier: float = 1.0
    control_weakness_factor: float = 1.0
    evidence_confidence_factor: float = 1.0
    inherent_risk: float
    residual_risk: float
    trace: List[RiskTraceEntry] = Field(default_factory=list)


class EnterpriseRiskMetrics(AISPRBaseModel):
    """
    Strict separation of enterprise risk metrics:
    1. Compliance Score
    2. Security Posture
    3. Residual Risk
    4. Attack Surface Risk
    5. Evidence Confidence
    6. Control Coverage
    """
    # 1. Compliance Score
    compliance_score: float = Field(ge=0.0, le=100.0)
    compliance_percentage_by_domain: Dict[str, float] = Field(default_factory=dict)

    # 2. Security Posture
    security_posture_score: float = Field(ge=0.0, le=100.0)
    security_posture_tier: PostureTier

    # 3. Residual Risk
    residual_risk_score: float = Field(ge=0.0, le=100.0)
    residual_risk_tier: RiskLevel
    unmitigated_finding_floor: float = Field(ge=0.0, le=100.0)

    # 4. Attack Surface Risk
    attack_surface_risk_score: float = Field(ge=0.0, le=100.0)
    attack_surface_risk_tier: RiskLevel

    # 5. Evidence Confidence
    evidence_confidence_score: float = Field(ge=0.0, le=100.0)
    live_evidence_count: int = 0
    simulated_evidence_count: int = 0
    missing_evidence_count: int = 0

    # 6. Control Coverage (Separated Truthful Dimensions)
    control_coverage_score: float = Field(ge=0.0, le=100.0)
    implementation_coverage: float = Field(default=0.0, ge=0.0, le=100.0)
    declared_coverage: float = Field(default=0.0, ge=0.0, le=100.0)
    evidence_coverage: float = Field(default=0.0, ge=0.0, le=100.0)
    assessment_coverage: float = Field(default=0.0, ge=0.0, le=100.0)
    automated_controls_count: int = 0
    manual_controls_count: int = 0
    implemented_controls_count: int = 0
    partial_controls_count: int = 0
    declared_controls_count: int = 0
    justified_na_count: int = 0
    unjustified_na_count: int = 0


class EnterpriseRiskResult(AISPRBaseModel):
    """
    Complete, explainable, versioned result output from the Enterprise AI Risk Engine.
    """
    assessment_id: str
    calculated_at: datetime = Field(default_factory=utc_now)
    risk_model_version: str = "1.0.0"
    formula_version: str = "2026.1-enterprise"
    metrics: EnterpriseRiskMetrics
    finding_assessments: List[FindingRiskAssessment] = Field(default_factory=list)
    calculation_trace: List[RiskTraceEntry] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
