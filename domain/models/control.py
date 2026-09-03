# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - Control & ControlResult Entities
"""

from datetime import datetime
from typing import List, Optional, Any
from pydantic import Field, field_validator

from domain.enums import ControlEvaluation, ControlRelationType, FindingSeverity
from domain.models.base import AISPRBaseModel, utc_now
from domain.models.framework import FrameworkMapping


class ControlLink(AISPRBaseModel):
    """
    Structured relationship linking a security finding to a specific GRC control.
    Explicitly differentiates between Primary Root Cause, Secondary, and Related controls.
    """
    control_id: str
    relation_type: ControlRelationType = Field(default=ControlRelationType.PRIMARY_CONTROL)
    rationale: Optional[str] = None

    @field_validator("relation_type", mode="before")
    @classmethod
    def parse_relation_type(cls, v: Any) -> ControlRelationType:
        if isinstance(v, str):
            normalized = v.upper().replace(" ", "_")
            try:
                return ControlRelationType(normalized)
            except ValueError:
                raise ValueError(f"Invalid ControlRelationType: '{v}'")
        return v


class Control(AISPRBaseModel):
    """
    Canonical definition of an AI-SPR GRC control (from the 104-Control Taxonomy).
    """
    control_id: str
    domain: str
    question: str
    criticality: FindingSeverity = Field(default=FindingSeverity.MEDIUM)
    rationale: str = ""
    framework_mappings: List[FrameworkMapping] = Field(default_factory=list)
    suggested_mitigation: Optional[str] = None

    @field_validator("criticality", mode="before")
    @classmethod
    def parse_criticality(cls, v: Any) -> FindingSeverity:
        if isinstance(v, str):
            try:
                return FindingSeverity(v.upper().strip())
            except ValueError:
                raise ValueError(f"Invalid FindingSeverity: '{v}'")
        return v


class ControlResult(AISPRBaseModel):
    """
    Evaluation verdict, score, and auditor annotations for a specific control.
    """
    control_id: str
    evaluation: ControlEvaluation = Field(default=ControlEvaluation.UNASSESSED)
    score: float = Field(default=0.0)
    criticality: FindingSeverity = Field(default=FindingSeverity.MEDIUM)
    auditor_notes: Optional[str] = None
    suggested_evaluation: Optional[ControlEvaluation] = None
    finding_ids: List[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=utc_now)
    evaluator: Optional[str] = None

    @field_validator("evaluation", mode="before")
    @classmethod
    def parse_evaluation(cls, v: Any) -> ControlEvaluation:
        if isinstance(v, str):
            val = v.upper().strip()
            if val in ("Y", "YES", "MET"):
                return ControlEvaluation.MET
            if val in ("N", "NO", "NOT_MET"):
                return ControlEvaluation.NOT_MET
            if val in ("P", "PARTIAL", "PARTIALLY_MET"):
                return ControlEvaluation.PARTIALLY_MET
            if val in ("NA", "N/A", "NOT_APPLICABLE"):
                return ControlEvaluation.NOT_APPLICABLE
            try:
                return ControlEvaluation(val)
            except ValueError:
                raise ValueError(f"Invalid ControlEvaluation: '{v}'")
        return v

    @field_validator("score", mode="before")
    @classmethod
    def compute_score_from_evaluation(cls, v: Any, info: Any) -> float:
        if v is not None and isinstance(v, (int, float)):
            return float(v)
        return 0.0
