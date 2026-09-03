# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - Remediation Entity
"""

import uuid
from typing import Optional, Dict, Any
from pydantic import Field, field_validator

from domain.enums import CloudProvider, FindingSeverity
from domain.models.base import AISPRBaseModel


class Remediation(AISPRBaseModel):
    """
    Actionable hardening guidance, Terraform blueprint, Model Armor policy, or IAM patch.
    """
    remediation_id: str = Field(default_factory=lambda: f"REM-{uuid.uuid4().hex[:8].upper()}")
    title: str
    description: str
    remediation_type: str = Field(default="TERRAFORM", description="TERRAFORM, MODEL_ARMOR_CONFIG, IAM_POLICY, MANUAL")
    target_cloud: CloudProvider = Field(default=CloudProvider.GCP)
    target_resource: str = Field(default="")
    priority: FindingSeverity = Field(default=FindingSeverity.HIGH)
    automated_remediation_available: bool = False
    code_snippet: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    estimated_effort: Optional[str] = None

    @field_validator("priority", mode="before")
    @classmethod
    def parse_priority(cls, v: Any) -> FindingSeverity:
        if isinstance(v, str):
            try:
                return FindingSeverity(v.upper())
            except ValueError:
                return FindingSeverity.HIGH
        return v

    @field_validator("target_cloud", mode="before")
    @classmethod
    def parse_cloud(cls, v: Any) -> CloudProvider:
        if isinstance(v, str):
            val = v.lower()
            try:
                return CloudProvider(val)
            except ValueError:
                return CloudProvider.UNKNOWN
        return v
