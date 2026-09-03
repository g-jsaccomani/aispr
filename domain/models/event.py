# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - SecurityEvent Entity
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import Field, field_validator

from domain.enums import CloudProvider, FindingSeverity, FindingSource
from domain.models.base import AISPRBaseModel, utc_now


class SecurityEvent(AISPRBaseModel):
    """
    Real-time security or telemetry event captured by Model Armor, Cloud Logging,
    or active runtime defense monitors.
    """
    event_id: str = Field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:8].upper()}")
    event_type: str
    timestamp: datetime = Field(default_factory=utc_now)
    source: FindingSource = Field(default=FindingSource.MODEL_ARMOR)
    provider: CloudProvider = Field(default=CloudProvider.GCP)
    severity: FindingSeverity = Field(default=FindingSeverity.HIGH)
    message: str = ""
    associated_finding_id: Optional[str] = None
    associated_asset_id: Optional[str] = None
    raw_payload: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity", mode="before")
    @classmethod
    def parse_severity(cls, v: Any) -> FindingSeverity:
        if isinstance(v, str):
            try:
                return FindingSeverity(v.upper())
            except ValueError:
                return FindingSeverity.HIGH
        return v
