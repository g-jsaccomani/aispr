# -*- coding: utf-8 -*-
"""
Copyright © 2026 Google LLC. Developed by Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - Risk Entity
"""

import uuid
from typing import List, Optional, Any
from pydantic import Field, field_validator

from domain.enums import RiskLevel
from domain.models.base import AISPRBaseModel


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
                return RiskLevel.MEDIUM
        return v
