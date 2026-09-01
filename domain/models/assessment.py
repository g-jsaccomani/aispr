# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - Assessment & AssessmentRun Entities
"""

import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import Field, field_validator

from domain.enums import AssessmentStatus, ExecutionMode, FindingSeverity
from domain.models.base import AISPRBaseModel, utc_now
from domain.models.asset import AIAsset
from domain.models.finding import SecurityFinding
from domain.models.control import ControlResult


class Assessment(AISPRBaseModel):
    """
    Top-level organizational posture review engagement.
    """
    assessment_id: str = Field(default_factory=lambda: f"ASM-{uuid.uuid4().hex[:8].upper()}")
    tenant_id: str = Field(default="enterprise-tenant-default")
    client_name: str = Field(default="Enterprise Customer")
    scope_description: str = Field(default="Multi-Cloud AI Estate (GCP, AWS, Azure)")
    status: AssessmentStatus = Field(default=AssessmentStatus.PLANNED)
    lead_assessor: str = Field(default="@jsaccomani (Google Cloud Security Consultant)")
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("status", mode="before")
    @classmethod
    def parse_status(cls, v: Any) -> AssessmentStatus:
        if isinstance(v, str):
            try:
                return AssessmentStatus(v.upper())
            except ValueError:
                return AssessmentStatus.PLANNED
        return v


class AssessmentRun(AISPRBaseModel):
    """
    Evidence-First Execution Run within an assessment engagement.
    Carries operational versions, scope, and guarantees all attached findings link back to this run.
    """
    assessment_id: str
    run_id: str = Field(default_factory=lambda: f"RUN-{uuid.uuid4().hex[:8].upper()}")
    tenant_id: Optional[str] = Field(default="enterprise-tenant-default")
    scope: str = Field(default="Multi-Cloud AI Estate (GCP, AWS, Azure)")
    execution_mode: ExecutionMode = Field(default=ExecutionMode.SIMULATION)
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = None
    
    # Engine & Governance Version Tracking
    tool_version: str = Field(default="AISPR-2.0.0")
    connector_versions: Dict[str, str] = Field(
        default_factory=lambda: {
            "gcp_connector": "2.0.0-live-partial",
            "aws_connector": "1.0.0-simulation",
            "azure_connector": "1.0.0-simulation"
        }
    )
    policy_version: str = Field(default="2026.Q3-Enterprise-v1")
    framework_versions: Dict[str, str] = Field(
        default_factory=lambda: {
            "Google SAIF": "2.0 (6 Core Pillars)",
            "NIST AI RMF": "1.0 (Jan 2023)",
            "ISO/IEC 42001": "2023 (Annex A Controls)",
            "MITRE ATLAS": "v4.2.0 (AML.T0000 - AML.T0060)",
            "EU AI Act": "2024/1689 (High-Risk Governance)",
            "OWASP Top 10": "GenAI & LLM 2025/2026"
        }
    )
    status: AssessmentStatus = Field(default=AssessmentStatus.IN_PROGRESS)
    
    assets: List[AIAsset] = Field(default_factory=list)
    findings: List[SecurityFinding] = Field(default_factory=list)
    control_results: List[ControlResult] = Field(default_factory=list)
    
    overall_score: Optional[float] = None
    posture_tier: Optional[str] = None
    summary_counts: Dict[str, int] = Field(default_factory=dict)

    @field_validator("execution_mode", mode="before")
    @classmethod
    def parse_execution_mode(cls, v: Any) -> ExecutionMode:
        if isinstance(v, str):
            try:
                return ExecutionMode(v.upper())
            except ValueError:
                return ExecutionMode.SIMULATION
        return v

    def add_finding(self, finding: SecurityFinding) -> "AssessmentRun":
        """
        Associates a finding with this specific AssessmentRun, ensuring alignment
        between assessment_id, run_id, and execution mode.
        """
        finding.assessment_id = self.assessment_id
        finding.metadata["run_id"] = self.run_id
        finding.metadata["run_execution_mode"] = str(self.execution_mode)
        self.findings.append(finding)
        return self

    def complete(self, overall_score: Optional[float] = None, posture_tier: Optional[str] = None):
        """Marks the assessment run as completed and computes summary counts."""
        self.status = AssessmentStatus.COMPLETED
        self.completed_at = utc_now()
        self.overall_score = overall_score
        self.posture_tier = posture_tier

        crit_count = sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)
        high_count = sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)
        med_count = sum(1 for f in self.findings if f.severity == FindingSeverity.MEDIUM)
        low_count = sum(1 for f in self.findings if f.severity == FindingSeverity.LOW)
        
        live_findings_count = sum(1 for f in self.findings if f.is_live_verified)
        sim_findings_count = sum(1 for f in self.findings if f.is_simulated)

        self.summary_counts = {
            "total_assets": len(self.assets),
            "total_findings": len(self.findings),
            "critical_findings": crit_count,
            "high_findings": high_count,
            "medium_findings": med_count,
            "low_findings": low_count,
            "live_verified_findings": live_findings_count,
            "simulated_findings": sim_findings_count,
            "evaluated_controls": len(self.control_results)
        }
